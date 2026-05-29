import base64
import copy
import hashlib
from io import BytesIO
from pathlib import Path
from typing import Literal

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from lxml import etree, isoschematron

from main import build_example

_REPO_ROOT = Path(__file__).parent.parent.parent
_XSD_PATH = _REPO_ROOT / "dlms-shipment-file-2026-05.xsd"
_SCH_PATH = _REPO_ROOT / "dlms-shipment.sch"
_NS = "https://open-metering.org/schemas/dlms-shipment-file/2026-05"
_NS_DS = "http://www.w3.org/2000/09/xmldsig#"

Profile = Literal["transfer", "shipment"]
_PROFILES: list[Profile] = ["transfer", "shipment"]


@pytest.fixture(scope="module")
def signing_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build(profile: Profile, signing_key: RSAPrivateKey | None = None) -> etree._Element:
    recipient_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return etree.fromstring(build_example(profile, recipient_key.public_key(), signing_key))


@pytest.fixture(scope="module")
def docs() -> dict[Profile, etree._Element]:
    # Unsigned variant per profile; signing is covered separately.
    return {profile: _build(profile) for profile in _PROFILES}


@pytest.mark.parametrize("profile", _PROFILES)
def test_xsd_valid(docs: dict[Profile, etree._Element], profile: Profile) -> None:
    schema = etree.XMLSchema(etree.parse(str(_XSD_PATH)))
    assert schema.validate(docs[profile]), schema.error_log


@pytest.mark.parametrize("profile", _PROFILES)
def test_schematron_valid(docs: dict[Profile, etree._Element], profile: Profile) -> None:
    schematron = isoschematron.Schematron(etree.parse(str(_SCH_PATH)), store_report=True)
    assert schematron.validate(docs[profile]), etree.tostring(
        schematron.validation_report, pretty_print=True
    ).decode()


@pytest.mark.parametrize("profile", _PROFILES)
def test_profile_attribute(docs: dict[Profile, etree._Element], profile: Profile) -> None:
    assert docs[profile].get("profile") == profile


def test_two_devices(docs: dict[Profile, etree._Element]) -> None:
    assert len(docs["shipment"].findall(f".//{{{_NS}}}Device")) == 2


def test_shipment_has_manufacturing_info(docs: dict[Profile, etree._Element]) -> None:
    assert docs["shipment"].find(f".//{{{_NS}}}ManufacturingInfo") is not None


def test_transfer_omits_manufacturing_info(docs: dict[Profile, etree._Element]) -> None:
    assert docs["transfer"].find(f".//{{{_NS}}}ManufacturingInfo") is None


@pytest.mark.parametrize("profile", _PROFILES)
def test_signature_valid(profile: Profile, signing_key: RSAPrivateKey) -> None:
    doc = _build(profile, signing_key)

    sig_el = doc.find(f"{{{_NS_DS}}}Signature")
    assert sig_el is not None, "No ds:Signature element found"

    signed_info = sig_el.find(f"{{{_NS_DS}}}SignedInfo")
    assert signed_info is not None

    digest_value_b64 = signed_info.findtext(f".//{{{_NS_DS}}}DigestValue")
    sig_value_b64 = sig_el.findtext(f"{{{_NS_DS}}}SignatureValue")
    assert digest_value_b64 and sig_value_b64

    # Verify document digest: C14N of the document with Signature removed
    # (the enveloped-signature transform).
    doc_copy = copy.deepcopy(doc)
    doc_copy.remove(doc_copy.find(f"{{{_NS_DS}}}Signature"))
    doc_c14n = _c14n(doc_copy)
    assert hashlib.sha256(doc_c14n).digest() == base64.b64decode(digest_value_b64.strip())

    # Verify the RSA-SHA256 signature over the C14N of SignedInfo.
    si_c14n = _c14n(signed_info)
    signing_key.public_key().verify(
        base64.b64decode(sig_value_b64.strip()),
        si_c14n,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def _c14n(element: etree._Element) -> bytes:
    buf = BytesIO()
    etree.ElementTree(element).write_c14n(buf, exclusive=False, with_comments=False)
    return buf.getvalue()
