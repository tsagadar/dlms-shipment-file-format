from pathlib import Path
from typing import Literal

import pytest
import validation
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from lxml import etree

from main import build_example

_REPO_ROOT = Path(__file__).parent.parent.parent
_XSD = _REPO_ROOT / "dlms-shipment-file-2026-05.xsd"
_SCH = _REPO_ROOT / "dlms-shipment.sch"
_TEST_DIR = _REPO_ROOT / "test"
_NS_DS = "http://www.w3.org/2000/09/xmldsig#"

Profile = Literal["transfer", "shipment"]

# test/invalid-*.xml -> the check expected to fail for each fixture.
_XSD_FAILURES = [
    "invalid-duplicate-credentialgroup-identity.xml",
    "invalid-duplicate-g3plcmacaddress.xml",
    "invalid-duplicate-logicaldevicename.xml",
    "invalid-duplicate-systemtitle.xml",
    "invalid-mixed-case-systemtitle.xml",
]
_SCHEMATRON_FAILURES = [
    "invalid-eappsk-in-suite-scoped-group.xml",
    "invalid-keyname-only-recipient.xml",
    "invalid-kw-no-kekref.xml",
    "invalid-other-no-name.xml",
    "invalid-plaintext-no-flag.xml",
]


@pytest.fixture(scope="module")
def recipient_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def signing_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _result(report: validation.ValidationReport, name: str) -> validation.CheckResult:
    return next(r for r in report.results if r.name == name)


def _format(report: validation.ValidationReport) -> str:
    return "\n".join(f"{r.name}: {r.status} {r.detail}" for r in report.results)


@pytest.mark.parametrize("profile", ["transfer", "shipment"])
@pytest.mark.parametrize("signed", [False, True])
def test_valid_file_passes(
    profile: Profile, signed: bool, recipient_key: RSAPrivateKey, signing_key: RSAPrivateKey
) -> None:
    xml = build_example(profile, recipient_key.public_key(), signing_key if signed else None)
    report = validation.validate_file(
        xml,
        xsd_path=_XSD,
        sch_path=_SCH,
        manufacturer_public_key=signing_key.public_key(),
        recipient_private_key=recipient_key,
    )
    assert report.ok, _format(report)
    assert _result(report, "signature").status == ("pass" if signed else "na")
    assert _result(report, "encrypted credentials").status == "pass"


@pytest.mark.parametrize("filename", _XSD_FAILURES)
def test_invalid_file_fails_xsd(filename: str) -> None:
    report = validation.validate_file((_TEST_DIR / filename).read_bytes(), xsd_path=_XSD, sch_path=_SCH)
    assert not report.ok
    assert _result(report, "XSD schema").status == "fail"


@pytest.mark.parametrize("filename", _SCHEMATRON_FAILURES)
def test_invalid_file_fails_schematron(filename: str) -> None:
    report = validation.validate_file((_TEST_DIR / filename).read_bytes(), xsd_path=_XSD, sch_path=_SCH)
    assert not report.ok
    assert _result(report, "XSD schema").status == "pass"
    assert _result(report, "Schematron rules").status == "fail"


def test_signed_file_without_manufacturer_key_fails(
    recipient_key: RSAPrivateKey, signing_key: RSAPrivateKey
) -> None:
    xml = build_example("transfer", recipient_key.public_key(), signing_key)
    report = validation.validate_file(
        xml,
        xsd_path=_XSD,
        sch_path=_SCH,
        manufacturer_public_key=None,
        recipient_private_key=recipient_key,
    )
    assert not report.ok
    assert _result(report, "signature").status == "fail"


def test_tampered_signature_fails(recipient_key: RSAPrivateKey, signing_key: RSAPrivateKey) -> None:
    xml = build_example("transfer", recipient_key.public_key(), signing_key)
    doc = etree.fromstring(xml)
    sv = doc.find(f".//{{{_NS_DS}}}SignatureValue")
    sv.text = ("B" if sv.text[0] == "A" else "A") + sv.text[1:]
    assert validation.verify_signature(doc, signing_key.public_key()).status == "fail"


def test_wrong_recipient_key_fails(recipient_key: RSAPrivateKey) -> None:
    xml = build_example("transfer", recipient_key.public_key())
    doc = etree.fromstring(xml)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert validation.check_encrypted_credentials(doc, other).status == "fail"


def test_encrypted_credentials_without_key_fails(recipient_key: RSAPrivateKey) -> None:
    xml = build_example("transfer", recipient_key.public_key())
    doc = etree.fromstring(xml)
    assert validation.check_encrypted_credentials(doc, None).status == "fail"


def test_malformed_xml_fails() -> None:
    report = validation.validate_file(b"<not-xml", xsd_path=_XSD, sch_path=_SCH)
    assert not report.ok
    assert _result(report, "well-formed XML").status == "fail"
