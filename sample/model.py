"""Data model for the DLMS shipment file format.

Pure dataclasses with no third-party dependencies, shared by the write side
(``generator.ShipmentFileBuilder``) and the read side (``importer``).  On the
write side ``Credential.key_bytes`` holds plaintext key material to be wrapped;
on the read side it holds the material an importer has just unwrapped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Literal

CredentialType = Literal[
    "MasterKey",
    "GlobalUnicastEncryption",
    "GlobalAuthentication",
    "Secret",
    "EapPsk",
    "Other",
]


@dataclass
class Credential:
    type: CredentialType
    key_bytes: bytes
    name: str | None = None  # required when type="Other"
    generated_at: datetime | None = None


@dataclass
class CredentialGroup:
    credentials: list[Credential]
    security_suite: int | None = None  # present for suite-scoped groups (0, 1, or 2)
    client_id: int | None = None       # present for suite-scoped groups (0–127)
    name: str | None = None
    comment: str | None = None         # emitted as an XML comment before the group


@dataclass
class ManufacturingInfo:
    """Optional per-device manufacturing metadata; shipment profile only."""

    device_type_designation: str | None = None
    hardware_version: str | None = None
    firmware_versions: list[str] = field(default_factory=list)
    manufacturing_date: date | None = None
    configuration_hash: str | None = None


@dataclass
class Device:
    system_title: str  # 16 uppercase hex chars, e.g. "414D50677015871E"
    logical_device_name: str
    credential_groups: list[CredentialGroup]
    g3_plc_mac_address: str | None = None  # EUI-64, 16 uppercase hex chars; G3-PLC meters only
    manufacturing_info: ManufacturingInfo | None = None
    comment: str | None = None  # emitted as an XML comment before the device


@dataclass
class DeviceRef:
    system_title: str  # references Device/@systemTitle


@dataclass
class Box:
    id: str
    device_refs: list[DeviceRef]


@dataclass
class Pallet:
    id: str
    boxes: list[Box]


@dataclass
class Logistics:
    pallets: list[Pallet]
    delivery_note: str | None = None
    purchase_order: str | None = None
    date: date | None = None
