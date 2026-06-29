import asyncio
import logging
import ssl
import struct
import time
from dataclasses import dataclass
from enum import StrEnum

import anyio
import trustme
from anyio.abc import SocketAttribute, SocketStream, UDPSocket
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


class DnsTransport(StrEnum):
    UDP = "udp"
    TCP = "tcp"
    TLS = "tls"


@dataclass(frozen=True)
class DnsClientContext:
    transport: DnsTransport
    remote_address: str
    remote_port: int


class DnsServer:
    def __init__(self, query_timeout: float = 10, response_timeout: float = 10) -> None:
        self.logger = logging.getLogger(__name__).getChild(self.__class__.__name__)
        self.query_timeout = query_timeout
        self.response_timeout = response_timeout

    async def run(
        self,
        host: str,
        listen_udp: bool | int = True,
        listen_tcp: bool | int = True,
        listen_tls: bool | int = False,
        certfile: str | None = None,
        keyfile: str | None = None,
    ) -> None:
        """Start the DNS server"""

        async with asyncio.TaskGroup() as tg:
            if listen_udp:
                tg.create_task(
                    self.udp_server(
                        host=host, port=53 if listen_udp is True else listen_udp
                    )
                )
            if listen_tcp:
                tg.create_task(
                    self.tcp_server(
                        host=host, port=53 if listen_tcp is True else listen_tcp
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

    async def udp_server(self, host: str, port: int) -> None:
        """Start UDP server to listen for DNS message"""

        self.logger.info("DNS UDP server listening to %s:%d", host, port)

        async with await anyio.create_udp_socket(
            local_host=host, local_port=port
        ) as udp:
            async for packet, (remote_address, remote_port) in udp:
                await self.handle_udp_client(udp, packet, remote_address, remote_port)

    async def tcp_server(self, host: str, port: int) -> None:
        """Start TCP server to listen for DNS message"""

        self.logger.info("DNS TCP server listening to %s:%d", host, port)

        listener = await anyio.create_tcp_listener(local_host=host, local_port=port)
        await listener.serve(self.handle_tcp_client)

    async def tls_server(
        self,
        host: str,
        port: int,
        certfile: str | None = None,
        keyfile: str | None = None,
    ) -> None:
        """Start TLS server to listen for DNS message"""

        self.logger.info("DNS TLS server listening to %s:%d", host, port)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        if certfile:
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        else:
            # Create a self-signed certificate for localhost using trustme
            trustme.CA().issue_cert("localhost").configure_cert(context)

        listener = TLSListener(
            await anyio.create_tcp_listener(local_host=host, local_port=port),
            context,
        )

        await listener.serve(self.handle_tcp_client)

    async def handle_udp_client(
        self, udp: UDPSocket, packet: bytes, remote_address: str, remote_port: int
    ) -> None:
        """Process UDP queries and responses"""

        self.logger.debug("UDP packet from %s:%d", remote_address, remote_port)

        client_context = DnsClientContext(
            transport=DnsTransport.UDP,
            remote_address=remote_address,
            remote_port=remote_port,
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
            for response in responses:
                raw_response = response.to_wire(multi=multi)
                await udp.sendto(raw_response, remote_address, remote_port)

    async def handle_tcp_client(self, client: SocketStream) -> None:
        """Process TCP queries and responses"""

        remote_address, remote_port = client.extra(SocketAttribute.remote_address)  # type: ignore

        if isinstance(client, TLSStream):
            self.logger.debug(
                "TLS connection from %s:%d",
                remote_address,
                remote_port,
            )
            client_context = DnsClientContext(
                transport=DnsTransport.TLS,
                remote_address=remote_address,
                remote_port=remote_port,
            )
        else:
            self.logger.debug("TCP connection from %s:%d", remote_address, remote_port)
            client_context = DnsClientContext(
                transport=DnsTransport.TCP,
                remote_address=remote_address,
                remote_port=remote_port,
            )
        try:
            while True:
                raw_data: bytes = b""
                async with asyncio.timeout(self.query_timeout):
                    if query_length_bytes := await client.receive(2):
                        if len(query_length_bytes) < 2:
                            raise ValueError("Received incomplete query length")
                        query_length = struct.unpack("!H", query_length_bytes)
                        raw_data = await client.receive(query_length[0])
                        if len(raw_data) < query_length[0]:
                            raise ValueError("Received incomplete query data")

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
                            await client.send(raw_response)
                        self.logger.debug("Returned %d DNS messages", len(responses))
        except anyio.EndOfStream:
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

        try:
            if len(query.question) == 0:
                raise ValueError("No question in query")
            elif len(query.question) > 1:
                raise ValueError("Multiple queries not yet supported")
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

        match (opcode, str(qname), rdtype, rdclass):
            case (
                dns.opcode.QUERY,
                "localhost.example.com.",
                dns.rdatatype.A,
                dns.rdataclass.IN,
            ):
                self.logger.info(
                    f"Handling {dns.rdatatype.to_text(rdtype)}/{dns.rdataclass.to_text(rdclass)} query for {qname} "
                    + f"from {client_context.transport} client "
                    + f"at {client_context.remote_address}:{client_context.remote_port}"
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

    server = DnsServer()

    asyncio.run(
        server.run(host=host, listen_tcp=port, listen_udp=port, listen_tls=tls_port)
    )


if __name__ == "__main__":
    main()
