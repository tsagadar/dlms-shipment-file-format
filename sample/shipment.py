from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding
from lxml import etree

_NS = "https://open-metering.org/schemas/dlms-shipment-file/2026-05"
_NS_XENC = "http://www.w3.org/2001/04/xmlenc#"
_ALGO_RSA_OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
_ALGO_KW_AES256_PAD = "http://www.w3.org/2009/xmlenc11#kw-aes-256-pad"

CredentialType = Literal[
    "MasterKey", "GlobalUnicastEncryption", "GlobalAuthentication", "EapPsk", "Other"
]


@dataclass
class Credential:
    type: CredentialType
    key_bytes: bytes
    name: str | None = None  # required when type="Other"
    generated_at: datetime | None = None


@dataclass
class DlmsKeySet:
    security_suite: int  # 0, 1, or 2
    client_id: int  # 0–127
    credentials: list[Credential]
    name: str | None = None


@dataclass
class LogicalDevice:
    logical_device_name: str
    key_sets: list[DlmsKeySet]
    network_credentials: list[Credential] = field(default_factory=list)


@dataclass
class Device:
    system_title: str  # 16 uppercase hex chars, e.g. "414D50677015871E"
    logical_devices: list[LogicalDevice]


class ShipmentFileBuilder:
    def __init__(
        self,
        recipient_public_key: RSAPublicKey,
        producer_customer: str | None = None,
        producer_manufacturer: str | None = None,
    ) -> None:
        self._recipient_public_key = recipient_public_key
        self._producer_customer = producer_customer
        self._producer_manufacturer = producer_manufacturer
        self._devices: list[Device] = []
        self._kek: bytes = b""  # populated during build()
        self._kek_id = "kek-1"

    def add_device(self, device: Device) -> ShipmentFileBuilder:
        self._devices.append(device)
        return self

    def build(self) -> bytes:
        self._kek = os.urandom(32)
        try:
            root = etree.Element(
                f"{{{_NS}}}ShipmentFile",
                nsmap={None: _NS, "xenc": _NS_XENC},
            )
            root.set("id", str(uuid4()))
            root.set("createdAt", datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
            root.set("schemaVersion", "2026-05")
            root.set("profile", "shipment")

            self._build_header(root)
            self._build_body(root)

            return etree.tostring(
                root, xml_declaration=True, encoding="UTF-8", pretty_print=True
            )
        finally:
            self._kek = b""

    def _build_header(self, parent: etree._Element) -> None:
        header = etree.SubElement(parent, f"{{{_NS}}}Header")

        attribs: dict[str, str] = {}
        if self._producer_customer:
            attribs["customer"] = self._producer_customer
        if self._producer_manufacturer:
            attribs["manufacturer"] = self._producer_manufacturer
        etree.SubElement(header, f"{{{_NS}}}Producer", attrib=attribs)

        # SubjectKeyIdentifier: SHA-1 of the PKCS#1 DER public key bytes (RFC 5280 method 1)
        pub_der = self._recipient_public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.PKCS1
        )
        ski = hashlib.sha1(pub_der).digest()

        # Wrap the 256-bit KEK with the recipient's RSA public key using OAEP/SHA-1
        wrapped_kek = self._recipient_public_key.encrypt(
            self._kek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )

        kek_el = etree.SubElement(header, f"{{{_NS}}}Kek", id=self._kek_id)
        etree.SubElement(kek_el, f"{{{_NS}}}EncryptionMethod", algorithm=_ALGO_RSA_OAEP)
        recipient_key_el = etree.SubElement(kek_el, f"{{{_NS}}}RecipientKey")
        ski_el = etree.SubElement(recipient_key_el, f"{{{_NS}}}SubjectKeyIdentifier")
        ski_el.text = base64.b64encode(ski).decode()
        cipher_data = etree.SubElement(kek_el, f"{{{_NS_XENC}}}CipherData")
        cipher_value = etree.SubElement(cipher_data, f"{{{_NS_XENC}}}CipherValue")
        cipher_value.text = base64.b64encode(wrapped_kek).decode()

    def _build_body(self, parent: etree._Element) -> None:
        body = etree.SubElement(parent, f"{{{_NS}}}Body")
        devices_el = etree.SubElement(body, f"{{{_NS}}}Devices")
        for device in self._devices:
            self._build_device(devices_el, device)

    def _build_device(self, parent: etree._Element, device: Device) -> None:
        device_el = etree.SubElement(
            parent, f"{{{_NS}}}Device", systemTitle=device.system_title
        )
        for ld in device.logical_devices:
            self._build_logical_device(device_el, ld)

    def _build_logical_device(self, parent: etree._Element, ld: LogicalDevice) -> None:
        ld_el = etree.SubElement(
            parent, f"{{{_NS}}}LogicalDevice", logicalDeviceName=ld.logical_device_name
        )

        if ld.network_credentials:
            net_creds_el = etree.SubElement(ld_el, f"{{{_NS}}}NetworkCredentials")
            for cred in ld.network_credentials:
                self._build_credential(net_creds_el, cred)

        for key_set in ld.key_sets:
            ks_attribs = {
                "securitySuite": str(key_set.security_suite),
                "clientId": str(key_set.client_id),
            }
            if key_set.name:
                ks_attribs["name"] = key_set.name
            ks_el = etree.SubElement(ld_el, f"{{{_NS}}}DlmsKeySet", attrib=ks_attribs)
            for cred in key_set.credentials:
                self._build_credential(ks_el, cred)

    def _build_credential(self, parent: etree._Element, cred: Credential) -> None:
        cred_attribs: dict[str, str] = {"type": cred.type}
        if cred.name:
            cred_attribs["name"] = cred.name
        cred_el = etree.SubElement(parent, f"{{{_NS}}}Credential", attrib=cred_attribs)

        etree.SubElement(
            cred_el, f"{{{_NS}}}EncryptionMethod", algorithm=_ALGO_KW_AES256_PAD
        )
        etree.SubElement(cred_el, f"{{{_NS}}}KekRef", kek=self._kek_id)

        wrapped_key = aes_key_wrap_with_padding(self._kek, cred.key_bytes)
        cipher_data = etree.SubElement(cred_el, f"{{{_NS_XENC}}}CipherData")
        cipher_value = etree.SubElement(cipher_data, f"{{{_NS_XENC}}}CipherValue")
        cipher_value.text = base64.b64encode(wrapped_key).decode()

        if cred.generated_at:
            gen_at_el = etree.SubElement(cred_el, f"{{{_NS}}}GeneratedAt")
            gen_at_el.text = cred.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
