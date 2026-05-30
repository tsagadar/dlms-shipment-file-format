# DLMS Shipment File — sample app

A small, dependency-light Python reference implementation of the shipment file
format (see [`../README.md`](../README.md) for the format spec itself). It covers
the full lifecycle behind one CLI and a set of reusable libraries:

1. **generate** — produce the worked `example-*.xml` files; `generator.py` is the
   reusable *write* library.
2. **validate** — check a file (well-formed → XSD → Schematron → signature →
   encrypted credentials), print what passed, and exit non-zero on failure.
3. **import** — a reference *read* path: validate, then decrypt the credentials
   into plain data structures.

## Setup

Install [uv](https://docs.astral.sh/uv/) — it manages the Python version and the
`cryptography` / `lxml` dependencies for you. Every command below is run through
`uv run` from the repo root, so there is no virtualenv or `PYTHONPATH` to set up.

## Usage

### generate

```bash
uv run --project sample python sample/main.py            # `generate` is the default
uv run --project sample python sample/main.py generate
```

Writes the four `example-*.xml` files to the repo root and, into `sample/`, the
manufacturer `signing-public-key.pem` (verifies the signed examples) and a fresh
`recipient-private-key.pem` (decrypts the example credentials). Per the project
convention, never edit the `example-*.xml` by hand — change the builder and
regenerate.

### validate

```bash
uv run --project sample python sample/main.py validate example-shipment-signed.xml
```

```
Validating example-shipment-signed.xml

  [✓] well-formed XML
  [✓] XSD schema — dlms-shipment-file-2026-05.xsd
  [✓] Schematron rules — dlms-shipment.sch
  [✓] signature — RSA-SHA256 verified
  [✓] encrypted credentials — 1 KEK(s), 12 credentials unwrapped

PASS
```

`[✓]` passed, `[✗]` failed, `[–]` not applicable (e.g. an unsigned file). The
command exits `0` only if no check failed.

A check that *cannot run because a key is missing* counts as a failure: a file
that carries a signature with no `--manufacturer-public-key`, or encrypted
credentials with no `--recipient-private-key`, fails rather than being skipped.

| Option | Default | Used for |
|--------|---------|----------|
| `--manufacturer-public-key` | `sample/signing-public-key.pem` | verify the `ds:Signature` |
| `--recipient-private-key` | `sample/recipient-private-key.pem` | unwrap the KEK / decrypt credentials |
| `--xsd` | `dlms-shipment-file-2026-05.xsd` | XSD schema |
| `--schematron` | `dlms-shipment.sch` | Schematron rules |

The defaults point at the sample keys and the repo-root schema, so the generated
examples validate with no extra flags. (The recipient key is regenerated on each
`generate` run, so validate the examples from the same checkout that produced
them.)

### import

```bash
uv run --project sample python sample/main.py import example-shipment.xml
uv run --project sample python sample/main.py import example-shipment.xml --display-credentials
```

Runs the XSD / Schematron / signature gate, then decrypts. By default it prints
only metadata; `--display-credentials` additionally prints the decrypted key
bytes (hex). Same key/schema options as `validate`.

```
Imported 2 device(s)  [profile=shipment, customer=VOLT, manufacturer=AmpTech]
  Device 414D50677015871E (AMP677015871E)
    suite-independent          EapPsk                     16 bytes
    suite 0/client 1 management MasterKey                  16 bytes
    ...
```

## Using the libraries

The CLI is a thin shell over three importable modules; they take/return data and
never print or exit, so you can reuse them when building your own tooling.

**Build a file** (`generator.py` + `model.py`):

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from generator import ShipmentFileBuilder
from model import Device, CredentialGroup, Credential

recipient = rsa.generate_private_key(public_exponent=65537, key_size=2048)
xml = (
    ShipmentFileBuilder(recipient.public_key(), profile="transfer", producer_system="HES")
    .add_device(Device(
        system_title="414D50677015871E",
        logical_device_name="AMP677015871E",
        credential_groups=[CredentialGroup(
            security_suite=0, client_id=1, name="management",
            credentials=[Credential("MasterKey", b"\x00" * 16)],
        )],
    ))
    .build()  # -> bytes
)
```

**Validate a file** (`validation.py`):

```python
from pathlib import Path
import validation

report = validation.validate_file(
    Path("example-shipment-signed.xml").read_bytes(),
    xsd_path=Path("dlms-shipment-file-2026-05.xsd"),
    sch_path=Path("dlms-shipment.sch"),
    manufacturer_public_key=manufacturer_pub,  # required if the file is signed
    recipient_private_key=recipient_priv,       # required if credentials are encrypted
)
report.ok                       # overall result
for check in report.results:    # CheckResult(name, status, detail)
    ...
```

**Import a file** (`importer.py`) — returns the same `model` dataclasses the
builder consumes, with `Credential.key_bytes` now holding decrypted material:

```python
import importer

report, shipment = importer.import_file(
    Path("example-shipment.xml").read_bytes(),
    manufacturer_public_key=None,
    recipient_private_key=recipient_priv,
    xsd_path=Path("dlms-shipment-file-2026-05.xsd"),
    sch_path=Path("dlms-shipment.sch"),
)
if shipment is not None:        # None if a gate or decryption failed
    for device in shipment.devices:
        for group in device.credential_groups:
            for cred in group.credentials:
                cred.key_bytes  # decrypted key
```

## Project structure

```
sample/
├── main.py        CLI: generate | validate | import; console rendering + exit codes
├── model.py       dependency-free dataclasses (Device, Credential, CredentialGroup, …)
├── crypto.py      namespace/algorithm constants, C14N, signature verify, KEK/credential unwrap
├── generator.py   ShipmentFileBuilder — encrypts + (optionally) signs a shipment file
├── validation.py  presentation-free checks → CheckResult / ValidationReport
├── importer.py    validation gate + decryption → ImportedShipment (model dataclasses)
└── tests/         pytest suite
```

Layering (no cycles): `model.py` and `crypto.py` are the base; `generator.py`
(write) and `validation.py` (read) build on them; `importer.py` composes
`validation` + `crypto` + `model`; `main.py` wires it all to the CLI.

Key files written by `generate`:

| File | Role |
|------|------|
| `signing-private-key.pem` | Manufacturer signing key — committed and reused so the signed examples stay verifiable. |
| `signing-public-key.pem` | Its public half — the default `--manufacturer-public-key`. |
| `recipient-private-key.pem` | Recipient key for decrypting the examples — regenerated each run, git-ignored. |

## Tests

```bash
uv run --project sample pytest sample/      # unit + conformance tests
uv run --project sample ruff check sample/  # lint
```

`tests/` covers builder output (XSD, Schematron, signature), the validator
against the `../test/invalid-*.xml` fixtures and tampered-crypto cases, and the
generate → import round trip.
