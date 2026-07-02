import asyncio
import logging
import ssl
import struct
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum

import anyio
import trustme
from anyio.abc import SocketAttribute, SocketStream, UDPSocket
from anyio.streams.buffered import BufferedByteReceiveStream
from anyio.streams.tls import TLSListener, TLSStream

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset


class DnsTransport(StrEnum):
    UDP = "udp"
    TCP = "tcp"
    TLS = "tls"


@dataclass(frozen=True)
class DnsClientContext:
    transport: DnsTransport
    remote_address: str
    remote_port: int
    local_address: str | None = None
    local_port: int | None = None


class QueryRefused(Exception):

    def __init__(self, query: dns.message.Message) -> None:
        """Exception raised when a DNS query is refused."""

        self.query = query

        parameters: dict[str, str] = {
            "opcode": dns.opcode.to_text(self.query.opcode()),
            "id": str(self.query.id),
        }

        if query.question:
            parameters.update(
                {
                    "qname": query.question[0].name.to_text(),
                    "qtype": dns.rdatatype.to_text(query.question[0].rdtype),
                    "qclass": dns.rdataclass.to_text(query.question[0].rdclass),
                }
            )

        return super().__init__(
            "Query refused: "
            + ", ".join(f"{key}={value}" for key, value in parameters.items())
        )


class DnsServer(ABC):
    def __init__(self, query_timeout: float = 10, response_timeout: float = 10) -> None:
        self.logger = logging.getLogger(__name__).getChild(self.__class__.__name__)
        self.query_timeout = query_timeout
        self.response_timeout = response_timeout

    async def run(
        self,
        host: str | None = None,
        listen_udp: bool | int = True,
        listen_tcp: bool | int = True,
        listen_tls: bool | int = False,
        certfile: str | None = None,
        keyfile: str | None = None,
    ) -> None:
        """Start the DNS server"""

        async with asyncio.TaskGroup() as tg:
            if listen_udp:
                if host:
                    tg.create_task(
                        self.udp_server(
                            host=host,
                            port=53 if listen_udp is True else listen_udp,
                        )
                    )
                else:
                    # Listen to both all IPv4 and IPv6 addresses if no specific host is provided
                    tg.create_task(
                        self.udp_server(
                            host="0.0.0.0",
                            port=53 if listen_udp is True else listen_udp,
                        )
                    )
                    tg.create_task(
                        self.udp_server(
                            host="::",
                            port=53 if listen_udp is True else listen_udp,
                        )
                    )
            if listen_tcp:
                tg.create_task(
                    self.tcp_server(
                        host=host,
                        port=53 if listen_tcp is True else listen_tcp,
                    )
                )
            if listen_tls:
                tg.create_task(
                    self.tls_server(
                        host=host,
                        port=853 if listen_tls is True else listen_tls,
                        certfile=certfile,
                        keyfile=keyfile,
                    )
                )

    async def udp_server(
        self,
        host: str,
        port: int = 53,
    ) -> None:
        """Start UDP server to listen for DNS messages"""

        self.logger.info("DNS UDP server listening to %s:%d", host or "*", port)

        async with (
            await anyio.create_udp_socket(
                local_host=host,
                local_port=port,
            ) as udp_socket,
            anyio.create_task_group() as tg,
        ):
            async for packet, (remote_address, remote_port) in udp_socket:
                client_context = DnsClientContext(
                    transport=DnsTransport.UDP,
                    remote_address=remote_address,
                    remote_port=remote_port,
                    local_address=host,
                    local_port=port,
                )
                tg.start_soon(
                    self._handle_udp_client_safe, udp_socket, packet, client_context
                )

    async def _handle_udp_client_safe(
        self,
        udp_socket: UDPSocket,
        packet: bytes,
        client_context: DnsClientContext,
    ) -> None:
        """Handle a UDP client without letting errors escape to the server loop"""

        try:
            async with asyncio.timeout(self.response_timeout):
                await self.handle_udp_client(udp_socket, packet, client_context)
        except TimeoutError:
            self.logger.warning("Timeout handling message")
        except Exception as exc:
            self.logger.error(f"Error responding to DNS query: {exc}", exc_info=exc)

    async def tcp_server(
        self,
        host: str | None = None,
        port: int = 53,
    ) -> None:
        """Start TCP server to listen for DNS messages"""

        self.logger.info("DNS TCP server listening to %s:%d", host or "*", port)

        tcp_listener = await anyio.create_tcp_listener(local_host=host, local_port=port)

        await tcp_listener.serve(self.handle_tcp_client)

    async def tls_server(
        self,
        host: str | None = None,
        port: int = 853,
        certfile: str | None = None,
        keyfile: str | None = None,
        hostname: str | None = None,
    ) -> None:
        """Start TLS server to listen for DNS messages"""

        self.logger.info("DNS TLS server listening to %s:%d", host or "*", port)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        if certfile:
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        else:
            # Create a self-signed certificate for localhost using trustme
            trustme.CA().issue_cert(hostname or "localhost").configure_cert(context)

        tls_listener = TLSListener(
            await anyio.create_tcp_listener(local_host=host, local_port=port),
            context,
        )

        await tls_listener.serve(self.handle_tcp_client)

    async def handle_udp_client(
        self,
        udp_socket: UDPSocket,
        packet: bytes,
        client_context: DnsClientContext,
    ) -> None:
        """Process UDP queries and responses"""

        self.logger.debug(
            "UDP packet from %s:%d",
            client_context.remote_address,
            client_context.remote_port,
        )

        try:
            query = dns.message.from_wire(packet)
        except dns.exception.DNSException:
            return

        if responses := await self.handle_query(
            query=query,
            client_context=client_context,
        ):
            multi = len(responses) > 1
            self.logger.debug("Returning %d DNS messages", len(responses))  # type: ignore
            # Truncate responses that exceed the client's advertised EDNS
            # payload size (or the 512 byte default), setting the TC flag
            max_size = query.payload if query.edns >= 0 else 512
            for response in responses:
                raw_response = response.to_wire(
                    multi=multi, max_size=max_size, prefer_truncation=True
                )
                await udp_socket.sendto(
                    raw_response,
                    client_context.remote_address,
                    client_context.remote_port,
                )

    async def handle_tcp_client(
        self,
        socket_stream: SocketStream,
    ) -> None:
        """Process TCP queries and responses"""

        remote_address, remote_port = socket_stream.extra(SocketAttribute.remote_address)  # type: ignore
        local_address, local_port = socket_stream.extra(SocketAttribute.local_address)  # type: ignore

        if isinstance(socket_stream, TLSStream):
            self.logger.debug(
                "TLS connection from %s:%d",
                remote_address,
                remote_port,
            )
            client_context = DnsClientContext(
                transport=DnsTransport.TLS,
                remote_address=remote_address,
                remote_port=remote_port,
                local_address=local_address,
                local_port=local_port,
            )
        else:
            self.logger.debug("TCP connection from %s:%d", remote_address, remote_port)
            client_context = DnsClientContext(
                transport=DnsTransport.TCP,
                remote_address=remote_address,
                remote_port=remote_port,
                local_address=local_address,
                local_port=local_port,
            )
        buffered_stream = BufferedByteReceiveStream(socket_stream)

        try:
            while True:
                async with asyncio.timeout(self.query_timeout):
                    query_length_bytes = await buffered_stream.receive_exactly(2)
                    (query_length,) = struct.unpack("!H", query_length_bytes)
                    raw_data = await buffered_stream.receive_exactly(query_length)

                try:
                    query = dns.message.from_wire(raw_data)
                except dns.exception.DNSException as exc:
                    self.logger.warning(f"Invalid query: {exc}", exc_info=exc)
                    return

                async with asyncio.timeout(self.response_timeout):
                    if responses := await self.handle_query(
                        query=query,
                        client_context=client_context,
                    ):
                        for response in responses:
                            raw_response = response.to_wire(prepend_length=True)
                            await socket_stream.send(raw_response)
                        self.logger.debug("Returned %d DNS messages", len(responses))
        except (anyio.EndOfStream, anyio.IncompleteRead):
            self.logger.debug("TCP connection closed by client")
        except TimeoutError:
            self.logger.warning("Timeout handling message")
        except Exception as exc:
            self.logger.error(f"Error responding to DNS query: {exc}", exc_info=exc)

    async def handle_query(
        self,
        query: dns.message.Message,
        client_context: DnsClientContext,
    ) -> list[dns.message.Message] | None:
        """Handle DNS query message and return response messages if applicable"""

        t1 = time.perf_counter()

        if len(query.question) != 1:
            self.logger.warning(
                "Refusing query with %d questions", len(query.question)
            )
            response = dns.message.Message(query.id)
            response.set_opcode(query.opcode())
            response.flags = dns.flags.QR
            response.question = list(query.question)
            response.set_rcode(dns.rcode.FORMERR)
            return [response]

        try:
            return await self.query(query, client_context)

        except QueryRefused as exc:
            self.logger.warning(str(exc))
            response = dns.message.Message(query.id)
            response.set_opcode(query.opcode())
            response.flags = dns.flags.QR
            response.question = list(query.question)
            response.set_rcode(dns.rcode.REFUSED)
            return [response]

        except Exception as exc:
            self.logger.warning(f"Query processing failed: {exc}")
            response = dns.message.Message(query.id)
            response.set_opcode(query.opcode())
            response.flags = dns.flags.QR
            response.question = list(query.question)
            response.set_rcode(dns.rcode.SERVFAIL)
            return [response]

        finally:
            t2 = time.perf_counter()
            self.logger.debug("Created query response in %.3f seconds", t2 - t1)

    @abstractmethod
    async def query(
        self,
        query: dns.message.Message,
        client_context: DnsClientContext,
    ) -> list[dns.message.Message] | None:
        """Process DNS query message and return response messages if applicable"""
        pass


class ExampleDnsServer(DnsServer):
    """Example implementation of a DNS server that handles specific queries"""

    async def query(
        self,
        query: dns.message.Message,
        client_context: DnsClientContext,
    ) -> list[dns.message.Message] | None:
        """Process DNS query message and return response messages if applicable"""

        opcode = query.opcode()
        qname = query.question[0].name
        rdtype = query.question[0].rdtype
        rdclass = query.question[0].rdclass

        # Match the query against specific criteria and handle accordingly
        match (opcode, str(qname), rdtype, rdclass):
            case (
                dns.opcode.QUERY,
                "localhost.example.com.",
                dns.rdatatype.A,
                dns.rdataclass.IN,
            ):
                self.logger.info(
                    f"Handling {dns.rdatatype.to_text(rdtype)}/{dns.rdataclass.to_text(rdclass)} query for {qname}"
                    + f" from {client_context.transport} client"
                    + f" at {client_context.remote_address}:{client_context.remote_port}"
                    + f" on {client_context.local_address}:{client_context.local_port}"
                )
                # Here you would implement the logic to handle the A record query for localhost.example.com
                # For demonstration purposes, let's create a simple response
                response = dns.message.make_response(query)
                response.answer.append(
                    dns.rrset.from_text(
                        "localhost.example.com.",
                        300,
                        "IN",
                        "A",
                        "127.0.0.1",
                    )
                )
                return [response]
            case _:
                raise QueryRefused(query=query)


def main() -> None:
    """Run the DNS server"""

    logging.basicConfig(level=logging.DEBUG)

    host = "127.0.0.1"
    port = 5300
    tls_port = 8853

    server = ExampleDnsServer()

    asyncio.run(
        server.run(host=host, listen_tcp=port, listen_udp=port, listen_tls=tls_port)
    )


if __name__ == "__main__":
    main()
