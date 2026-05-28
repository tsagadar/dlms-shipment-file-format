from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree, isoschematron

from main import create_sample_shipment

_REPO_ROOT = Path(__file__).parent.parent.parent
_XSD_PATH = _REPO_ROOT / "dlms-shipment-file-2026-05.xsd"
_SCH_PATH = _REPO_ROOT / "dlms-shipment.sch"
_NS = "https://open-metering.org/schemas/dlms-shipment-file/2026-05"


@pytest.fixture(scope="module")
def sample_doc() -> etree._Element:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return etree.fromstring(create_sample_shipment(private_key.public_key()))


def test_xsd_valid(sample_doc: etree._Element) -> None:
    schema = etree.XMLSchema(etree.parse(str(_XSD_PATH)))
    assert schema.validate(sample_doc), schema.error_log


def test_schematron_valid(sample_doc: etree._Element) -> None:
    schematron = isoschematron.Schematron(
        etree.parse(str(_SCH_PATH)), store_report=True
    )
    assert schematron.validate(sample_doc), etree.tostring(
        schematron.validation_report, pretty_print=True
    ).decode()


def test_three_devices(sample_doc: etree._Element) -> None:
    devices = sample_doc.findall(f".//{{{_NS}}}Device")
    assert len(devices) == 3
