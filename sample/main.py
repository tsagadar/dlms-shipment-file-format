from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from shipment import Credential, CredentialGroup, Device, ShipmentFileBuilder

_GENERATED_AT = datetime(2026, 1, 27, 22, 43, 0, tzinfo=UTC)


def _key(system_title: str, purpose: str, length: int = 16) -> bytes:
    return hashlib.sha256(f"{system_title}/{purpose}".encode()).digest()[:length]


def create_sample_shipment(
    recipient_public_key: RSAPublicKey,
    signing_private_key: RSAPrivateKey | None = None,
) -> bytes:
    builder = ShipmentFileBuilder(
        recipient_public_key=recipient_public_key,
        producer_customer="ACME Utility",
        producer_manufacturer="SmartMeter Inc",
        signing_private_key=signing_private_key,
    )

    # Device 1 — VLT: G3-PLC meter with management and installer access levels
    st1 = "564C54677015871E"
    builder.add_device(
        Device(
            system_title=st1,
            logical_device_name="VLT677015871E",
            credential_groups=[
                CredentialGroup(
                    credentials=[
                        Credential(
                            type="EapPsk",
                            key_bytes=_key(st1, "EapPsk"),
                            generated_at=_GENERATED_AT,
                        ),
                    ],
                ),
                CredentialGroup(
                    security_suite=0,
                    client_id=1,
                    name="management",
                    credentials=[
                        Credential(
                            type="MasterKey",
                            key_bytes=_key(st1, "MasterKey"),
                            generated_at=_GENERATED_AT,
                        ),
                        Credential(
                            type="GlobalUnicastEncryption",
                            key_bytes=_key(st1, "GUEK"),
                            generated_at=_GENERATED_AT,
                        ),
                        Credential(
                            type="GlobalAuthentication",
                            key_bytes=_key(st1, "GAK"),
                            generated_at=_GENERATED_AT,
                        ),
                    ],
                ),
                CredentialGroup(
                    security_suite=0,
                    client_id=2,
                    name="installer",
                    credentials=[
                        Credential(
                            type="GlobalUnicastEncryption",
                            key_bytes=_key(st1, "GUEK-installer"),
                            generated_at=_GENERATED_AT,
                        ),
                        Credential(
                            type="GlobalAuthentication",
                            key_bytes=_key(st1, "GAK-installer"),
                            generated_at=_GENERATED_AT,
                        ),
                    ],
                ),
            ],
        )
    )

    # Device 2 — AMP: basic meter, management access only
    st2 = "414D500099887766"
    builder.add_device(
        Device(
            system_title=st2,
            logical_device_name="AMP0099887766",
            credential_groups=[
                CredentialGroup(
                    security_suite=0,
                    client_id=1,
                    name="management",
                    credentials=[
                        Credential(
                            type="MasterKey",
                            key_bytes=_key(st2, "MasterKey"),
                            generated_at=_GENERATED_AT,
                        ),
                        Credential(
                            type="GlobalUnicastEncryption",
                            key_bytes=_key(st2, "GUEK"),
                            generated_at=_GENERATED_AT,
                        ),
                        Credential(
                            type="GlobalAuthentication",
                            key_bytes=_key(st2, "GAK"),
                            generated_at=_GENERATED_AT,
                        ),
                    ],
                ),
            ],
        )
    )

    # Device 3 — OMS: dual-suite meter (suite 0 AES-128, suite 1 AES-256)
    st3 = "4F4D530012345678"
    builder.add_device(
        Device(
            system_title=st3,
            logical_device_name="OMS0012345678",
            credential_groups=[
                CredentialGroup(
                    security_suite=0,
                    client_id=1,
                    name="management",
                    credentials=[
                        Credential(
                            type="MasterKey",
                            key_bytes=_key(st3, "MasterKey"),
                            generated_at=_GENERATED_AT,
                        ),
                        Credential(
                            type="GlobalUnicastEncryption",
                            key_bytes=_key(st3, "GUEK"),
                            generated_at=_GENERATED_AT,
                        ),
                        Credential(
                            type="GlobalAuthentication",
                            key_bytes=_key(st3, "GAK"),
                            generated_at=_GENERATED_AT,
                        ),
                    ],
                ),
                CredentialGroup(
                    security_suite=1,
                    client_id=1,
                    name="management",
                    credentials=[
                        Credential(
                            type="MasterKey",
                            key_bytes=_key(st3, "MasterKey-s1", 32),
                            generated_at=_GENERATED_AT,
                        ),
                        Credential(
                            type="GlobalUnicastEncryption",
                            key_bytes=_key(st3, "GUEK-s1", 32),
                            generated_at=_GENERATED_AT,
                        ),
                        Credential(
                            type="GlobalAuthentication",
                            key_bytes=_key(st3, "GAK-s1", 32),
                            generated_at=_GENERATED_AT,
                        ),
                    ],
                ),
            ],
        )
    )

    return builder.build()


def main() -> None:
    recipient_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    xml_bytes = create_sample_shipment(recipient_key.public_key(), signing_key)

    Path("shipment-sample.xml").write_bytes(xml_bytes)
    Path("recipient-private-key.pem").write_bytes(
        recipient_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    Path("signing-private-key.pem").write_bytes(
        signing_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    print(f"Written shipment-sample.xml ({len(xml_bytes)} bytes)")
    print("Written recipient-private-key.pem")
    print("Written signing-private-key.pem")


if __name__ == "__main__":
    main()
