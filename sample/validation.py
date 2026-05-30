"""Reusable, presentation-free validation of shipment files.

Each check returns a :class:`CheckResult`; :func:`validate_file` runs them in
order and collects a :class:`ValidationReport`.  Nothing here prints or exits —
the CLI in ``main.py`` renders the report and chooses the exit code.

Check statuses:
- ``pass`` — the check ran and succeeded.
- ``fail`` — the check ran and failed, *or* it could not run because a required
  key was missing (a present signature with no manufacturer public key, or
  encrypted credentials with no recipient private key).
- ``na``   — the check does not apply to this file (no signature; no encrypted
  credentials).  Does not affect the overall result.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from lxml import etree, isoschematron

import crypto
from crypto import ALGO_NONE, NS, NS_DS

_NS_SVRL = "http://purl.oclc.org/dsdl/svrl"

Status = Literal["pass", "fail", "na"]


@dataclass
class CheckResult:
    name: str
    status: Status
    detail: str = ""


@dataclass
class ValidationReport:
    results: list[CheckResult]

    @property
    def ok(self) -> bool:
        return all(r.status != "fail" for r in self.results)


def validate_well_formed(xml_bytes: bytes) -> tuple[CheckResult, etree._Element | None]:
    try:
        doc = etree.fromstring(xml_bytes)
    except etree.XMLSyntaxError as exc:
        return CheckResult("well-formed XML", "fail", str(exc)), None
    return CheckResult("well-formed XML", "pass"), doc


def validate_xsd(doc: etree._Element, xsd_path: Path) -> CheckResult:
    schema = etree.XMLSchema(etree.parse(str(xsd_path)))
    if schema.validate(doc):
        return CheckResult("XSD schema", "pass", xsd_path.name)
    return CheckResult("XSD schema", "fail", str(schema.error_log))


def validate_schematron(doc: etree._Element, sch_path: Path) -> CheckResult:
    schematron = isoschematron.Schematron(etree.parse(str(sch_path)), store_report=True)
    if schematron.validate(doc):
        return CheckResult("Schematron rules", "pass", sch_path.name)
    return CheckResult("Schematron rules", "fail", _schematron_failures(schematron))


def verify_signature(
    doc: etree._Element, manufacturer_public_key: RSAPublicKey | None
) -> CheckResult:
    if doc.find(f"{{{NS_DS}}}Signature") is None:
        return CheckResult("signature", "na", "no ds:Signature (unsigned file)")
    if manufacturer_public_key is None:
        return CheckResult(
            "signature",
            "fail",
            "signature present but no manufacturer public key provided",
        )
    try:
        crypto.verify_signature(doc, manufacturer_public_key)
    except Exception as exc:  # InvalidSignature, ValueError, ...
        return CheckResult("signature", "fail", f"{type(exc).__name__}: {exc}")
    return CheckResult("signature", "pass", "RSA-SHA256 verified")


def check_encrypted_credentials(
    doc: etree._Element, recipient_private_key: RSAPrivateKey | None
) -> CheckResult:
    name = "encrypted credentials"
    encrypted = [c for c in _credentials(doc) if _cred_algorithm(c) != ALGO_NONE]
    if not encrypted:
        return CheckResult(name, "na", "no encrypted credentials")
    if recipient_private_key is None:
        return CheckResult(
            name, "fail", "encrypted credentials present but no recipient private key provided"
        )

    try:
        keks = crypto.unwrap_all_keks(doc, recipient_private_key)
    except Exception as exc:
        return CheckResult(name, "fail", f"KEK unwrap failed: {type(exc).__name__}: {exc}")

    for cred in encrypted:
        ref = cred.find(f"{{{NS}}}KekRef")
        kek_id = ref.get("kek") if ref is not None else None
        kek = keks.get(kek_id) if kek_id is not None else None
        if kek is None:
            return CheckResult(name, "fail", f"credential references unknown KEK {kek_id!r}")
        try:
            crypto.unwrap_credential(kek, crypto.cipher_value(cred))
        except Exception as exc:
            return CheckResult(
                name, "fail", f"credential unwrap failed: {type(exc).__name__}: {exc}"
            )

    return CheckResult(
        name, "pass", f"{len(keks)} KEK(s), {len(encrypted)} credentials unwrapped"
    )


def validate_file(
    xml_bytes: bytes,
    *,
    xsd_path: Path,
    sch_path: Path,
    manufacturer_public_key: RSAPublicKey | None = None,
    recipient_private_key: RSAPrivateKey | None = None,
) -> ValidationReport:
    well_formed, doc = validate_well_formed(xml_bytes)
    results = [well_formed]
    if doc is None:
        return ValidationReport(results)
    results.append(validate_xsd(doc, xsd_path))
    results.append(validate_schematron(doc, sch_path))
    results.append(verify_signature(doc, manufacturer_public_key))
    results.append(check_encrypted_credentials(doc, recipient_private_key))
    return ValidationReport(results)


# --- helpers ---------------------------------------------------------------


def _credentials(doc: etree._Element) -> list[etree._Element]:
    return doc.findall(f".//{{{NS}}}Credential")


def _cred_algorithm(cred: etree._Element) -> str | None:
    method = cred.find(f"{{{NS}}}EncryptionMethod")
    return method.get("algorithm") if method is not None else None


def _schematron_failures(schematron: isoschematron.Schematron) -> str:
    report = schematron.validation_report
    texts = [
        " ".join((t.text or "").split())
        for t in report.findall(f".//{{{_NS_SVRL}}}failed-assert/{{{_NS_SVRL}}}text")
    ]
    if texts:
        return "; ".join(texts)
    return etree.tostring(report, pretty_print=True).decode()
