"""Reusable reference implementation of *importing* a shipment file.

``import_file`` runs the conformance gate (XSD, Schematron, signature) reusing
:mod:`validation`, then decrypts the KEK(s) and credentials and returns the
result as the same :mod:`model` dataclasses the generator consumes — with
``Credential.key_bytes`` now holding the decrypted key material.  This is the
round trip: build → file → import.

Like :mod:`validation` it is presentation-free; ``main.py`` renders the report
and the imported devices.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from lxml import etree

import crypto
import validation
from crypto import ALGO_NONE, NS
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
from validation import CheckResult, ValidationReport


@dataclass
class ImportedShipment:
    profile: str | None
    producer_customer: str | None
    producer_manufacturer: str | None
    producer_system: str | None
    devices: list[Device]
    logistics: Logistics | None


def import_file(
    xml_bytes: bytes,
    *,
    manufacturer_public_key: RSAPublicKey | None,
    recipient_private_key: RSAPrivateKey | None,
    xsd_path: Path,
    sch_path: Path,
) -> tuple[ValidationReport, ImportedShipment | None]:
    """Validate and decrypt a shipment file.

    Returns the validation report plus the imported shipment, or ``None`` for the
    shipment if any check (the XSD/Schematron/signature gate, or decryption)
    failed.
    """
    well_formed, doc = validation.validate_well_formed(xml_bytes)
    results = [well_formed]
    if doc is None:
        return ValidationReport(results), None

    results.append(validation.validate_xsd(doc, xsd_path))
    results.append(validation.validate_schematron(doc, sch_path))
    results.append(validation.verify_signature(doc, manufacturer_public_key))
    gate = ValidationReport(results)
    if not gate.ok:
        return gate, None

    decrypt_result, shipment = _decrypt(doc, recipient_private_key)
    results.append(decrypt_result)
    report = ValidationReport(results)
    return report, (shipment if report.ok else None)


def _decrypt(
    doc: etree._Element, recipient_private_key: RSAPrivateKey | None
) -> tuple[CheckResult, ImportedShipment | None]:
    name = "decrypted credentials"
    has_encrypted = any(
        _cred_algorithm(c) != ALGO_NONE for c in doc.findall(f".//{{{NS}}}Credential")
    )
    if has_encrypted and recipient_private_key is None:
        return (
            CheckResult(name, "fail", "encrypted credentials present but no recipient private key provided"),
            None,
        )

    try:
        keks = (
            crypto.unwrap_all_keks(doc, recipient_private_key)
            if recipient_private_key is not None
            else {}
        )
        devices = [_parse_device(d, keks) for d in doc.findall(f".//{{{NS}}}Device")]
        logistics = _parse_logistics(doc)
    except Exception as exc:
        return CheckResult(name, "fail", f"{type(exc).__name__}: {exc}"), None

    producer = doc.find(f"{{{NS}}}Header/{{{NS}}}Producer")
    shipment = ImportedShipment(
        profile=doc.get("profile"),
        producer_customer=producer.get("customer") if producer is not None else None,
        producer_manufacturer=producer.get("manufacturer") if producer is not None else None,
        producer_system=producer.get("system") if producer is not None else None,
        devices=devices,
        logistics=logistics,
    )
    total = sum(len(g.credentials) for d in devices for g in d.credential_groups)
    return CheckResult(name, "pass", f"{len(keks)} KEK(s), {total} credentials"), shipment


# --- XML -> model ----------------------------------------------------------


def _parse_device(dev_el: etree._Element, keks: dict[str, bytes]) -> Device:
    identifiers = dev_el.find(f"{{{NS}}}Identifiers")
    return Device(
        system_title=dev_el.get("systemTitle", ""),
        logical_device_name=(
            identifiers.findtext(f"{{{NS}}}LogicalDeviceName", "") if identifiers is not None else ""
        ),
        g3_plc_mac_address=(
            identifiers.findtext(f"{{{NS}}}G3PlcMacAddress") if identifiers is not None else None
        ),
        manufacturing_info=_parse_manufacturing(dev_el),
        credential_groups=[
            _parse_group(g, keks) for g in dev_el.findall(f"{{{NS}}}CredentialGroup")
        ],
    )


def _parse_group(grp_el: etree._Element, keks: dict[str, bytes]) -> CredentialGroup:
    suite = grp_el.get("securitySuite")
    client = grp_el.get("clientId")
    return CredentialGroup(
        credentials=[_parse_credential(c, keks) for c in grp_el.findall(f"{{{NS}}}Credential")],
        security_suite=int(suite) if suite is not None else None,
        client_id=int(client) if client is not None else None,
        name=grp_el.get("name"),
    )


def _parse_credential(cred_el: etree._Element, keks: dict[str, bytes]) -> Credential:
    cipher = crypto.cipher_value(cred_el)
    if _cred_algorithm(cred_el) == ALGO_NONE:
        key_bytes = cipher
    else:
        ref = cred_el.find(f"{{{NS}}}KekRef")
        kek_id = ref.get("kek") if ref is not None else None
        kek = keks.get(kek_id) if kek_id is not None else None
        if kek is None:
            raise ValueError(f"credential references unknown KEK {kek_id!r}")
        key_bytes = crypto.unwrap_credential(kek, cipher)
    return Credential(
        type=cred_el.get("type"),  # type: ignore[arg-type]
        key_bytes=key_bytes,
        name=cred_el.get("name"),
        generated_at=_parse_dt(cred_el.findtext(f"{{{NS}}}GeneratedAt")),
    )


def _parse_manufacturing(dev_el: etree._Element) -> ManufacturingInfo | None:
    el = dev_el.find(f"{{{NS}}}ManufacturingInfo")
    if el is None:
        return None
    made = el.findtext(f"{{{NS}}}ManufacturingDate")
    return ManufacturingInfo(
        device_type_designation=el.findtext(f"{{{NS}}}DeviceTypeDesignation"),
        hardware_version=el.findtext(f"{{{NS}}}HardwareVersion"),
        firmware_versions=[fw.text for fw in el.findall(f"{{{NS}}}FirmwareVersion") if fw.text],
        manufacturing_date=date.fromisoformat(made) if made else None,
        configuration_hash=el.findtext(f"{{{NS}}}ConfigurationHash"),
    )


def _parse_logistics(doc: etree._Element) -> Logistics | None:
    el = doc.find(f".//{{{NS}}}Logistics")
    if el is None:
        return None
    pallets = [
        Pallet(
            id=p.get("id", ""),
            boxes=[
                Box(
                    id=b.get("id", ""),
                    device_refs=[
                        DeviceRef(r.get("systemTitle", ""))
                        for r in b.findall(f"{{{NS}}}DeviceRef")
                    ],
                )
                for b in p.findall(f"{{{NS}}}Box")
            ],
        )
        for p in el.findall(f"{{{NS}}}Pallet")
    ]
    made = el.get("date")
    return Logistics(
        pallets=pallets,
        delivery_note=el.get("deliveryNote"),
        purchase_order=el.get("purchaseOrder"),
        date=date.fromisoformat(made) if made else None,
    )


def _cred_algorithm(cred: etree._Element) -> str | None:
    method = cred.find(f"{{{NS}}}EncryptionMethod")
    return method.get("algorithm") if method is not None else None


def _parse_dt(text: str | None) -> datetime | None:
    if not text:
        return None
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
