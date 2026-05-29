from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from shipment import (
    Credential,
    CredentialGroup,
    Device,
    ManufacturingInfo,
    ShipmentFileBuilder,
)

_GENERATED_AT = datetime(2026, 1, 27, 22, 43, 0, tzinfo=UTC)
_REPO_ROOT = Path(__file__).parent.parent

_ST1 = "414D50677015871E"  # G3-PLC meter
_ST2 = "414D500099887766"  # non-G3 meter

_MAC1 = "001BC50C7015871E"  # G3-PLC EUI-64 of the first meter

_KEK_COMMENT = "Single recipient => exactly one KEK, RSA-OAEP wrapped to the recipient's key."


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
    return builder.build()


def _load_or_create_signing_key() -> RSAPrivateKey:
    # Reuse the committed signing key so the committed signed examples verify
    # against it; only generate (and write) one if it is missing.
    path = _REPO_ROOT / "sample" / "signing-private-key.pem"
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        assert isinstance(key, RSAPrivateKey)
        return key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return key


def main() -> None:
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

    # The recipient private key is needed to unwrap the KEK; write it next to the
    # sample so a reader can decrypt the example credentials.
    (_REPO_ROOT / "sample" / "recipient-private-key.pem").write_bytes(
        recipient_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    print("Written sample/recipient-private-key.pem")


if __name__ == "__main__":
    main()
