from pathlib import Path

import importer
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from main import _ST1, _ST2, _key, build_example

_REPO_ROOT = Path(__file__).parent.parent.parent
_XSD = _REPO_ROOT / "dlms-shipment-file-2026-05.xsd"
_SCH = _REPO_ROOT / "dlms-shipment.sch"
_TEST_DIR = _REPO_ROOT / "test"


@pytest.fixture(scope="module")
def recipient_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def signing_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_round_trip_decrypts_to_original_keys(
    recipient_key: RSAPrivateKey, signing_key: RSAPrivateKey
) -> None:
    xml = build_example("shipment", recipient_key.public_key(), signing_key)
    report, shipment = importer.import_file(
        xml,
        manufacturer_public_key=signing_key.public_key(),
        recipient_private_key=recipient_key,
        xsd_path=_XSD,
        sch_path=_SCH,
    )
    assert report.ok
    assert shipment is not None
    assert shipment.profile == "shipment"
    assert {d.system_title for d in shipment.devices} == {_ST1, _ST2}

    dev1 = next(d for d in shipment.devices if d.system_title == _ST1)
    # First group is the suite-independent EapPsk group.
    eap = dev1.credential_groups[0].credentials[0]
    assert eap.type == "EapPsk"
    assert eap.key_bytes == _key(_ST1, "EapPsk")
    # A suite-scoped credential round-trips too.
    master = dev1.credential_groups[1].credentials[0]
    assert master.type == "MasterKey"
    assert master.key_bytes == _key(_ST1, "MasterKey")


def test_logistics_round_trips(recipient_key: RSAPrivateKey) -> None:
    xml = build_example("shipment", recipient_key.public_key())
    _, shipment = importer.import_file(
        xml,
        manufacturer_public_key=None,
        recipient_private_key=recipient_key,
        xsd_path=_XSD,
        sch_path=_SCH,
    )
    assert shipment is not None
    assert shipment.logistics is not None
    refs = shipment.logistics.pallets[0].boxes[0].device_refs
    assert {r.system_title for r in refs} == {_ST1, _ST2}


def test_invalid_file_returns_no_shipment() -> None:
    bad = (_TEST_DIR / "invalid-mixed-case-systemtitle.xml").read_bytes()
    report, shipment = importer.import_file(
        bad, manufacturer_public_key=None, recipient_private_key=None, xsd_path=_XSD, sch_path=_SCH
    )
    assert not report.ok
    assert shipment is None


def test_import_without_recipient_key_fails(recipient_key: RSAPrivateKey) -> None:
    xml = build_example("transfer", recipient_key.public_key())
    report, shipment = importer.import_file(
        xml, manufacturer_public_key=None, recipient_private_key=None, xsd_path=_XSD, sch_path=_SCH
    )
    assert not report.ok
    assert shipment is None
