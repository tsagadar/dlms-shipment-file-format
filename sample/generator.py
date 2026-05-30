from __future__ import annotations

import base64
import hashlib
import os
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding
from lxml import etree

from crypto import (
    ALGO_C14N as _ALGO_C14N,
    ALGO_ENVELOPED as _ALGO_ENVELOPED,
    ALGO_KW_AES256_PAD as _ALGO_KW_AES256_PAD,
    ALGO_RSA_OAEP as _ALGO_RSA_OAEP,
    ALGO_RSA_SHA256 as _ALGO_RSA_SHA256,
    ALGO_SHA256 as _ALGO_SHA256,
    NS as _NS,
    NS_DS as _NS_DS,
    NS_XENC as _NS_XENC,
    c14n as _c14n,
)
from model import Credential, Device, Logistics, ManufacturingInfo


class ShipmentFileBuilder:
    def __init__(
        self,
        recipient_public_key: RSAPublicKey,
        profile: Literal["transfer", "shipment"] = "shipment",
        producer_customer: str | None = None,
        producer_manufacturer: str | None = None,
        producer_system: str | None = None,
        signing_private_key: RSAPrivateKey | None = None,
        kek_comment: str | None = None,
    ) -> None:
        self._recipient_public_key = recipient_public_key
        self._profile = profile
        self._producer_customer = producer_customer
        self._producer_manufacturer = producer_manufacturer
        self._producer_system = producer_system
        self._signing_key = signing_private_key
        self._kek_comment = kek_comment
        self._devices: list[Device] = []
        self._logistics: Logistics | None = None
        self._kek: bytes = b""  # populated during build()
        self._kek_id = "kek-1"

    def add_device(self, device: Device) -> ShipmentFileBuilder:
        self._devices.append(device)
        return self

    def set_logistics(self, logistics: Logistics) -> ShipmentFileBuilder:
        self._logistics = logistics
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
            root.set("profile", self._profile)

            self._build_header(root)
            self._build_body(root)

            if self._signing_key is not None:
                self._apply_signature(root)
                # Signed documents must not be pretty-printed: extra whitespace
                # text nodes would change the C14N digest and break verification.
                return etree.tostring(root, xml_declaration=True, encoding="UTF-8")

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
        if self._producer_system:
            attribs["system"] = self._producer_system
        etree.SubElement(header, f"{{{_NS}}}Producer", attrib=attribs)

        _comment(header, self._kek_comment)

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
            _comment(devices_el, device.comment)
            self._build_device(devices_el, device)
        if self._logistics is not None:
            self._build_logistics(body, self._logistics)

    def _build_logistics(self, parent: etree._Element, logistics: Logistics) -> None:
        attribs: dict[str, str] = {}
        if logistics.delivery_note:
            attribs["deliveryNote"] = logistics.delivery_note
        if logistics.purchase_order:
            attribs["purchaseOrder"] = logistics.purchase_order
        if logistics.date:
            attribs["date"] = logistics.date.isoformat()
        logistics_el = etree.SubElement(parent, f"{{{_NS}}}Logistics", attrib=attribs)
        for pallet in logistics.pallets:
            pallet_el = etree.SubElement(logistics_el, f"{{{_NS}}}Pallet", id=pallet.id)
            for box in pallet.boxes:
                box_el = etree.SubElement(pallet_el, f"{{{_NS}}}Box", id=box.id)
                for ref in box.device_refs:
                    etree.SubElement(box_el, f"{{{_NS}}}DeviceRef", systemTitle=ref.system_title)

    def _build_device(self, parent: etree._Element, device: Device) -> None:
        device_el = etree.SubElement(
            parent,
            f"{{{_NS}}}Device",
            systemTitle=device.system_title,
        )

        # Identifiers carry the non-systemTitle identities; element order follows
        # the XSD sequence in IdentifiersType.
        identifiers_el = etree.SubElement(device_el, f"{{{_NS}}}Identifiers")
        etree.SubElement(identifiers_el, f"{{{_NS}}}LogicalDeviceName").text = (
            device.logical_device_name
        )
        if device.g3_plc_mac_address:
            etree.SubElement(identifiers_el, f"{{{_NS}}}G3PlcMacAddress").text = (
                device.g3_plc_mac_address
            )

        if device.manufacturing_info is not None:
            self._build_manufacturing_info(device_el, device.manufacturing_info)

        for group in device.credential_groups:
            _comment(device_el, group.comment)
            attribs: dict[str, str] = {}
            if group.security_suite is not None:
                attribs["securitySuite"] = str(group.security_suite)
            if group.client_id is not None:
                attribs["clientId"] = str(group.client_id)
            if group.name:
                attribs["name"] = group.name
            group_el = etree.SubElement(device_el, f"{{{_NS}}}CredentialGroup", attrib=attribs)
            for cred in group.credentials:
                self._build_credential(group_el, cred)

    def _build_manufacturing_info(
        self, parent: etree._Element, info: ManufacturingInfo
    ) -> None:
        el = etree.SubElement(parent, f"{{{_NS}}}ManufacturingInfo")
        # Element order follows the XSD sequence in ManufacturingInfoType.
        if info.device_type_designation:
            etree.SubElement(el, f"{{{_NS}}}DeviceTypeDesignation").text = (
                info.device_type_designation
            )
        if info.hardware_version:
            etree.SubElement(el, f"{{{_NS}}}HardwareVersion").text = info.hardware_version
        for firmware_version in info.firmware_versions:
            etree.SubElement(el, f"{{{_NS}}}FirmwareVersion").text = firmware_version
        if info.manufacturing_date:
            etree.SubElement(el, f"{{{_NS}}}ManufacturingDate").text = (
                info.manufacturing_date.isoformat()
            )
        if info.configuration_hash:
            etree.SubElement(el, f"{{{_NS}}}ConfigurationHash").text = info.configuration_hash

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

    def _apply_signature(self, root: etree._Element) -> None:
        # Digest: C14N of the document before the Signature element is appended
        # (equivalent to applying the enveloped-signature transform).
        doc_digest = hashlib.sha256(_c14n(root)).digest()

        # Build the Signature structure, appended as the last child of root.
        sig_el = etree.SubElement(root, f"{{{_NS_DS}}}Signature", nsmap={"ds": _NS_DS})
        signed_info = etree.SubElement(sig_el, f"{{{_NS_DS}}}SignedInfo")
        etree.SubElement(signed_info, f"{{{_NS_DS}}}CanonicalizationMethod", Algorithm=_ALGO_C14N)
        etree.SubElement(signed_info, f"{{{_NS_DS}}}SignatureMethod", Algorithm=_ALGO_RSA_SHA256)
        ref = etree.SubElement(signed_info, f"{{{_NS_DS}}}Reference", URI="")
        transforms = etree.SubElement(ref, f"{{{_NS_DS}}}Transforms")
        etree.SubElement(transforms, f"{{{_NS_DS}}}Transform", Algorithm=_ALGO_ENVELOPED)
        etree.SubElement(transforms, f"{{{_NS_DS}}}Transform", Algorithm=_ALGO_C14N)
        etree.SubElement(ref, f"{{{_NS_DS}}}DigestMethod", Algorithm=_ALGO_SHA256)
        dv_el = etree.SubElement(ref, f"{{{_NS_DS}}}DigestValue")
        dv_el.text = base64.b64encode(doc_digest).decode()

        # Sign the C14N of SignedInfo.  SignedInfo is already part of the root
        # tree, so _c14n picks up the inherited namespace context (including
        # the default shipment namespace and the ds: prefix).
        sig_bytes = self._signing_key.sign(  # type: ignore[union-attr]
            _c14n(signed_info),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        sv_el = etree.SubElement(sig_el, f"{{{_NS_DS}}}SignatureValue")
        sv_el.text = base64.b64encode(sig_bytes).decode()


def _comment(parent: etree._Element, text: str | None) -> None:
    if text:
        parent.append(etree.Comment(f" {text} "))
