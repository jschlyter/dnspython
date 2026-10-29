import argparse
import json
import logging
import os

from jwcrypto.jwk import JWK

import dns.dnssec
import dns.zone
from dns.dnssecalgs import algorithms
from dns.dnssecalgs.base import GenericPrivateKey

name_to_cls = {a.name.upper(): cls for ((a, _), cls) in algorithms.items()}


def load_private_key(filename: str) -> GenericPrivateKey:
    """Load a private key from a JWK file and return a GenericPrivateKey instance."""

    with open(filename, "rb") as fp:
        key_data = json.load(fp)

    if not (dnssec_algorithm := key_data.pop("dnssec_algorithm", None)):
        raise ValueError("Missing dnssec_algorithm in key data")

    if not (private_cls := name_to_cls.get(dnssec_algorithm)):
        raise ValueError(f"Unsupported algorithm: {dnssec_algorithm}")

    jwk = JWK(**key_data)
    if not jwk.has_private:
        raise ValueError("JWK does not contain a private key")

    return private_cls(jwk.get_op_key(operation="sign"))


def command_sign_zone(args: argparse.Namespace) -> None:
    """Sign a DNS zone with the provided KSK and ZSK keys."""

    keys: list[tuple[GenericPrivateKey, dns.dnssec.DNSKEY]] = []

    for ksk_file in args.ksk or []:
        private_key = load_private_key(ksk_file)
        keys.append(
            (
                private_key,
                private_key.public_key().to_dnskey(
                    flags=dns.dnssec.Flag.ZONE | dns.dnssec.Flag.SEP
                ),
            )
        )

    for zsk_file in args.zsk or []:
        private_key = load_private_key(zsk_file)
        keys.append((private_key, private_key.public_key().to_dnskey()))

    if not keys:
        raise ValueError("No keys provided for signing")

    zone = dns.zone.from_file(args.zone, relativize=False)

    with zone.writer() as txn:
        dns.dnssec.sign_zone(
            zone=zone,
            txn=txn,
            keys=keys,
            lifetime=args.lifetime,
        )

    if args.output:
        with open(args.output, "w") as fp:
            zone.to_file(fp, relativize=False, sorted=True)
    else:
        print(zone.to_text(relativize=False, sorted=True))


def command_generate_key(args: argparse.Namespace) -> None:
    """Generate a DNSSEC key and output it as a JWK."""

    alg = args.algorithm.upper()

    if (private_cls := name_to_cls.get(alg)) is None:
        raise ValueError(f"Unsupported algorithm: {args.algorithm}")

    match alg:
        case "RSAMD5" | "RSASHA1" | "RSASHA1NSEC3SHA1" | "RSASHA256" | "RSASHA512":
            if not args.size:
                raise ValueError("Key size must be specified for RSA algorithms")
            private_key = private_cls.generate(key_size=args.size)
        case "DSA" | "DSANSEC3SHA1":
            if not args.size:
                raise ValueError("Key size must be specified for DSA algorithms")
            private_key = private_cls.generate(key_size=args.size)
        case _:
            private_key = private_cls.generate()

    jwk = JWK.from_pyca(private_key.key)
    jwk["dnssec_algorithm"] = alg

    if args.output:
        with os.fdopen(
            os.open(args.output, os.O_WRONLY | os.O_CREAT, 0o600), "w"
        ) as fp:
            json.dump(jwk.export(as_dict=True), fp, indent=4)
    else:
        print(json.dumps(jwk.export(as_dict=True), indent=4))


def main():

    parser = argparse.ArgumentParser(description="DNSSEC Zone Signer")

    parser.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        help="Enable debugging",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    sign_zone_parser = subparsers.add_parser("sign-zone", help="Sign a DNS zone")
    sign_zone_parser.set_defaults(func=command_sign_zone)
    sign_zone_parser.add_argument(
        "--ksk",
        metavar="KSK",
        nargs="+",
        help="KSK file",
    )
    sign_zone_parser.add_argument(
        "--zsk",
        metavar="ZSK",
        nargs="+",
        help="ZSK file",
    )
    sign_zone_parser.add_argument(
        "--zone",
        metavar="ZONE_FILE",
        help="Zone file to sign",
        required=True,
    )
    sign_zone_parser.add_argument(
        "--lifetime",
        metavar="SECONDS",
        type=int,
        help="Signature lifetime in seconds",
        default=3600,
    )
    sign_zone_parser.add_argument(
        "--output",
        metavar="FILENAME",
        help="Output filename",
    )

    generate_key_parser = subparsers.add_parser(
        "generate-key", help="Generate a DNSSEC key"
    )
    generate_key_parser.set_defaults(func=command_generate_key)
    generate_key_parser.add_argument(
        "--output",
        metavar="FILENAME",
        help="Output filename",
    )
    generate_key_parser.add_argument(
        "--algorithm",
        metavar="ALGORITHM",
        help="Key algorithm",
        choices=name_to_cls.keys(),
        required=True,
    )
    generate_key_parser.add_argument(
        "--size",
        metavar="KEY_SIZE",
        type=int,
        help="Key size (required for RSA and DSA)",
        default=None,
    )

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    if not getattr(args, "func", None):
        parser.error("No command specified")

    args.func(args)


if __name__ == "__main__":
    main()
