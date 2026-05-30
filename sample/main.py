from __future__ import annotations

import argparse
import hashlib
import sys
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

import importer
import validation
from generator import ShipmentFileBuilder
from model import (
    Box,
    Credential,
    CredentialGroup,
    Device,
    DeviceRef,
    Logistics,
    ManufacturingInfo,
    Pallet,
)

_GENERATED_AT = datetime(2026, 1, 27, 22, 43, 0, tzinfo=UTC)
_REPO_ROOT = Path(__file__).parent.parent
_SAMPLE_DIR = Path(__file__).parent

_ST1 = "414D50677015871E"  # G3-PLC meter
_ST2 = "414D500099887766"  # non-G3 meter

_MAC1 = "001BC50C7015871E"  # G3-PLC EUI-64 of the first meter

_KEK_COMMENT = "Single recipient => exactly one KEK, RSA-OAEP wrapped to the recipient's key."

# Default artifact locations, so the committed examples validate/import with no
# extra flags (the keys here are written by `generate`).
_XSD_PATH = _REPO_ROOT / "dlms-shipment-file-2026-05.xsd"
_SCH_PATH = _REPO_ROOT / "dlms-shipment.sch"
_SIGNING_PRIVATE_KEY = _SAMPLE_DIR / "signing-private-key.pem"
_SIGNING_PUBLIC_KEY = _SAMPLE_DIR / "signing-public-key.pem"
_RECIPIENT_PRIVATE_KEY = _SAMPLE_DIR / "recipient-private-key.pem"


def _key(system_title: str, purpose: str, length: int = 16) -> bytes:
    return hashlib.sha256(f"{system_title}/{purpose}".encode()).digest()[:length]


def _devices(include_manufacturing: bool) -> list[Device]:
    """The canonical two-device set, shared by both profiles.

    Identities and keys are identical across profiles; the only difference is
    that the shipment profile attaches ManufacturingInfo, illustrating that a
    transfer file is a strict subset of a shipment file.
    """
    return [
        Device(
            system_title=_ST1,
            logical_device_name="AMP677015871E",
            g3_plc_mac_address=_MAC1,
            comment="First device: G3-PLC meter, management + installer access.",
            manufacturing_info=ManufacturingInfo(
                device_type_designation="EX-TD-M100A1B1C1",
                hardware_version="1.0.0",
                firmware_versions=["V000101"],
                manufacturing_date=date(2025, 6, 1),
                configuration_hash="c0ffeec0ffeec0ffeec0ffeec0ffeec0",
            )
            if include_manufacturing
            else None,
            credential_groups=[
                CredentialGroup(
                    comment="Suite-independent group: G3 network secret, no securitySuite/clientId.",
                    credentials=[
                        Credential("EapPsk", _key(_ST1, "EapPsk"), generated_at=_GENERATED_AT),
                    ],
                ),
                CredentialGroup(
                    security_suite=0,
                    client_id=1,
                    name="management",
                    comment="Management access level, security suite 0.",
                    credentials=[
                        Credential("MasterKey", _key(_ST1, "MasterKey"), generated_at=_GENERATED_AT),
                        Credential(
                            "GlobalUnicastEncryption", _key(_ST1, "GUEK"), generated_at=_GENERATED_AT
                        ),
                        Credential(
                            "GlobalAuthentication", _key(_ST1, "GAK"), generated_at=_GENERATED_AT
                        ),
                    ],
                ),
                CredentialGroup(
                    security_suite=2,
                    client_id=1,
                    name="management",
                    comment="Same access level provisioned for suite 2 (ECC) as well.",
                    credentials=[
                        Credential(
                            "GlobalUnicastEncryption",
                            _key(_ST1, "GUEK-s2", 32),
                            generated_at=_GENERATED_AT,
                        ),
                        Credential(
                            "GlobalAuthentication",
                            _key(_ST1, "GAK-s2", 32),
                            generated_at=_GENERATED_AT,
                        ),
                    ],
                ),
                CredentialGroup(
                    security_suite=0,
                    client_id=2,
                    name="installer",
                    comment="Installer access level, suite 0.",
                    credentials=[
                        Credential(
                            "GlobalUnicastEncryption",
                            _key(_ST1, "GUEK-installer"),
                            generated_at=_GENERATED_AT,
                        ),
                        Credential(
                            "GlobalAuthentication",
                            _key(_ST1, "GAK-installer"),
                            generated_at=_GENERATED_AT,
                        ),
                        Credential(
                            "Secret",
                            _key(_ST1, "Secret-installer"),
                            generated_at=_GENERATED_AT,
                        ),
                    ],
                ),
            ],
        ),
        Device(
            system_title=_ST2,
            logical_device_name="AMP0099887766",
            comment="Second device: non-G3 bearer, so no suite-independent group.",
            manufacturing_info=ManufacturingInfo(
                device_type_designation="EX-TD-M100A1B1C1",
                hardware_version="1.0.0",
                firmware_versions=["V000101"],
                manufacturing_date=date(2025, 6, 1),
            )
            if include_manufacturing
            else None,
            credential_groups=[
                CredentialGroup(
                    security_suite=0,
                    client_id=1,
                    name="management",
                    credentials=[
                        Credential("MasterKey", _key(_ST2, "MasterKey"), generated_at=_GENERATED_AT),
                        Credential(
                            "GlobalUnicastEncryption", _key(_ST2, "GUEK"), generated_at=_GENERATED_AT
                        ),
                        Credential(
                            "GlobalAuthentication", _key(_ST2, "GAK"), generated_at=_GENERATED_AT
                        ),
                    ],
                ),
            ],
        ),
    ]


def build_example(
    profile: Literal["transfer", "shipment"],
    recipient_public_key: RSAPublicKey,
    signing_private_key: RSAPrivateKey | None = None,
) -> bytes:
    """Build one example file for the given profile.

    shipment: manufacturer delivery — Producer carries customer/manufacturer and
              each Device carries ManufacturingInfo.
    transfer: system-to-system export — Producer names the producing system and
              no manufacturing metadata is present.
    """
    is_shipment = profile == "shipment"
    builder = ShipmentFileBuilder(
        recipient_public_key=recipient_public_key,
        profile=profile,
        producer_customer="VOLT" if is_shipment else None,
        producer_manufacturer="AmpTech" if is_shipment else None,
        producer_system=None if is_shipment else "VOLT-HES",
        signing_private_key=signing_private_key,
        kek_comment=_KEK_COMMENT,
    )
    for device in _devices(include_manufacturing=is_shipment):
        builder.add_device(device)
    if is_shipment:
        builder.set_logistics(
            Logistics(
                delivery_note="DN-2025-001",
                purchase_order="PO-2025-001",
                date=date(2025, 6, 1),
                pallets=[
                    Pallet(
                        id="PAL-001",
                        boxes=[
                            Box(id="BOX-001", device_refs=[DeviceRef(_ST1), DeviceRef(_ST2)]),
                        ],
                    )
                ],
            )
        )
    return builder.build()


def _load_or_create_signing_key() -> RSAPrivateKey:
    # Reuse the committed signing key so the committed signed examples verify
    # against it; only generate (and write) one if it is missing.
    if _SIGNING_PRIVATE_KEY.exists():
        key = serialization.load_pem_private_key(_SIGNING_PRIVATE_KEY.read_bytes(), password=None)
        assert isinstance(key, RSAPrivateKey)
        return key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _SIGNING_PRIVATE_KEY.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return key


# --- commands --------------------------------------------------------------


def cmd_generate(args: argparse.Namespace) -> int:
    recipient_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    recipient_pub = recipient_key.public_key()
    signing_key = _load_or_create_signing_key()

    outputs = {
        "example-transfer.xml": build_example("transfer", recipient_pub),
        "example-transfer-signed.xml": build_example("transfer", recipient_pub, signing_key),
        "example-shipment.xml": build_example("shipment", recipient_pub),
        "example-shipment-signed.xml": build_example("shipment", recipient_pub, signing_key),
    }
    for name, xml_bytes in outputs.items():
        (_REPO_ROOT / name).write_bytes(xml_bytes)
        print(f"Written {name} ({len(xml_bytes)} bytes)")

    # The manufacturer public key verifies the signed examples; the recipient
    # private key unwraps the KEK so a reader can decrypt the credentials.
    _SIGNING_PUBLIC_KEY.write_bytes(
        signing_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(f"Written sample/{_SIGNING_PUBLIC_KEY.name}")

    _RECIPIENT_PRIVATE_KEY.write_bytes(
        recipient_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    print(f"Written sample/{_RECIPIENT_PRIVATE_KEY.name}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.file)
    report = validation.validate_file(
        path.read_bytes(),
        xsd_path=args.xsd,
        sch_path=args.schematron,
        manufacturer_public_key=_load_public_key(args.manufacturer_public_key),
        recipient_private_key=_load_private_key(args.recipient_private_key),
    )
    print(f"Validating {path.name}\n")
    _render_report(report)
    print(f"\n{'PASS' if report.ok else 'FAIL'}")
    return 0 if report.ok else 1


def cmd_import(args: argparse.Namespace) -> int:
    path = Path(args.file)
    report, shipment = importer.import_file(
        path.read_bytes(),
        manufacturer_public_key=_load_public_key(args.manufacturer_public_key),
        recipient_private_key=_load_private_key(args.recipient_private_key),
        xsd_path=args.xsd,
        sch_path=args.schematron,
    )
    print(f"Importing {path.name}\n")
    _render_report(report)
    if shipment is None:
        print("\nFAIL")
        return 1
    print()
    _render_shipment(shipment, show_keys=args.display_credentials)
    print("\nPASS")
    return 0


# --- presentation ----------------------------------------------------------

_SYMBOL = {"pass": "✓", "fail": "✗", "na": "–"}


def _render_report(report: validation.ValidationReport) -> None:
    for result in report.results:
        mark = _SYMBOL[result.status]
        if result.detail and "\n" not in result.detail:
            print(f"  [{mark}] {result.name} — {result.detail}")
        else:
            print(f"  [{mark}] {result.name}")
            for line in result.detail.splitlines():
                print(f"        {line}")


def _render_shipment(shipment: importer.ImportedShipment, show_keys: bool) -> None:
    producer = ", ".join(
        f"{label}={value}"
        for label, value in (
            ("customer", shipment.producer_customer),
            ("manufacturer", shipment.producer_manufacturer),
            ("system", shipment.producer_system),
        )
        if value
    )
    suffix = f", {producer}" if producer else ""
    print(f"Imported {len(shipment.devices)} device(s)  [profile={shipment.profile}{suffix}]")
    for device in shipment.devices:
        print(f"  Device {device.system_title} ({device.logical_device_name})")
        for group in device.credential_groups:
            scope = _group_scope(group)
            for cred in group.credentials:
                label = cred.type + (f" [{cred.name}]" if cred.name else "")
                line = f"    {scope:<26} {label:<26} {len(cred.key_bytes):>2} bytes"
                if show_keys:
                    line += f"  {cred.key_bytes.hex()}"
                print(line)


def _group_scope(group: CredentialGroup) -> str:
    if group.security_suite is None:
        scope = "suite-independent"
    else:
        scope = f"suite {group.security_suite}/client {group.client_id}"
    return f"{scope} {group.name}" if group.name else scope


def _load_public_key(path: Path) -> RSAPublicKey | None:
    if not path.exists():
        return None
    key = serialization.load_pem_public_key(path.read_bytes())
    assert isinstance(key, RSAPublicKey)
    return key


def _load_private_key(path: Path) -> RSAPrivateKey | None:
    if not path.exists():
        return None
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    assert isinstance(key, RSAPrivateKey)
    return key


# --- CLI -------------------------------------------------------------------


def _add_io_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("file", help="path to the shipment XML file")
    parser.add_argument(
        "--manufacturer-public-key",
        type=Path,
        default=_SIGNING_PUBLIC_KEY,
        help="PEM public key used to verify the signature",
    )
    parser.add_argument(
        "--recipient-private-key",
        type=Path,
        default=_RECIPIENT_PRIVATE_KEY,
        help="PEM private key used to unwrap the KEK / decrypt credentials",
    )
    parser.add_argument("--xsd", type=Path, default=_XSD_PATH, help="path to the XSD schema")
    parser.add_argument(
        "--schematron", type=Path, default=_SCH_PATH, help="path to the Schematron rules"
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dlms-shipment",
        description="Generate, validate, and import DLMS shipment files.",
    )
    sub = parser.add_subparsers(dest="command")

    generate = sub.add_parser("generate", help="generate the example shipment files (default)")
    generate.set_defaults(func=cmd_generate)

    validate = sub.add_parser("validate", help="check a file against XSD, Schematron, signature, keys")
    _add_io_args(validate)
    validate.set_defaults(func=cmd_validate)

    import_ = sub.add_parser("import", help="validate then decrypt and import the credentials")
    _add_io_args(import_)
    import_.add_argument(
        "--display-credentials",
        action="store_true",
        help="also print the decrypted key material (hex)",
    )
    import_.set_defaults(func=cmd_import)

    # No subcommand => generate, preserving `python sample/main.py`.
    parser.set_defaults(func=cmd_generate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
