# Open DLMS/COSEM Shipment File Format

Version `2026-05` · namespace `https://open-metering.org/schemas/dlms-shipment-file/2026-05`

A vendor-neutral XML format for transporting DLMS smart-meter cryptographic
credentials together with the device identities they belong to. It replaces the
proprietary, mutually incompatible shipment files that meter manufacturers ship
today with a single, opinionated, standards-based format.

## Files in this package

| File | Purpose |
|------|---------|
| `dlms-shipment-file-2026-05.xsd` | The schema. Authoritative definition; the inline `xs:documentation` is part of the spec. |
| `dlms-shipment.sch` | ISO Schematron conformance rules. Enforces constraints that XSD 1.0 cannot express. Required for production conformance. |
| `xmldsig-stub.xsd`, `xmlenc-stub.xsd` | Minimal stubs for the W3C signature/encryption namespaces so the schema validates standalone. Replace with the official W3C schemas if you want full signature validation. |
| `example-shipment.xml` | A worked, schema-valid example (manufacturer-shipment profile, two devices). |
| `README.md` | This document. |

Validate with any XSD 1.0 processor, e.g.:

```bash
xmllint --schema dlms-shipment-file-2026-05.xsd example-shipment.xml --noout
```

Schematron validation (Python lxml):

```bash
python3 -c "
from lxml import etree, isoschematron
sch = isoschematron.Schematron(etree.parse('dlms-shipment.sch'), store_report=True)
doc = etree.parse('example-shipment.xml')
ok = sch.validate(doc)
print('OK' if ok else 'FAILED')
if not ok: print(etree.tostring(sch.validation_report, pretty_print=True).decode())
"
```

## Conformance levels

**Schema-valid** — passes `xmllint --schema dlms-shipment-file-2026-05.xsd`.
Necessary but not sufficient for production use.  The XSD cannot express
conditional rules (e.g. "kw-aes256-pad requires KekRef") or placement rules
(e.g. "EapPsk belongs only in NetworkCredentials").

**Conformance-valid** — passes both the XSD and `dlms-shipment.sch`.
Required for production use.  The Schematron file enforces all the
security and structural constraints that would otherwise be prose-only.

Production importers should reject files that fail either check.

## What problem this solves

A DLMS meter is provisioned with secret keys at manufacturing time. Those keys
must reach the utility's key-management system to be usable, and later may move
between systems (e.g. exported from a Head-End System and imported into a
calibration bench). Today every manufacturer uses its own file layout, so every
manufacturer-to-utility and system-to-system integration is a custom project.
This format is one container for both flows.

## Two use cases, one schema

* **Transfer (core).** Move keys from one system to another. Carries only what
  is needed: device identity + the keys.
* **Shipment (superset).** A manufacturer delivers freshly built meters. Adds
  optional per-device manufacturing metadata. (Packaging/order *logistics* will
  arrive in a later revision as a separate top-level section that references
  devices by system title — deliberately deferred so it can be bolted on
  without disturbing the core.)

The device element has the **same shape** in both profiles; shipment-only
information is optional and simply absent in a transfer file. A consumer that
understands the core can always read a shipment file. The root `profile`
attribute declares intent so validators/importers can apply stricter checks.

## Document shape

```
ShipmentFile            (id, createdAt, schemaVersion, allowPlaintextKeys, profile)
├── Header
│   ├── Producer        (customer / manufacturer / system)
│   └── Kek 1..N        one symmetric KEK per recipient key pair
│       ├── EncryptionMethod   (rsa-oaep-mgf1p | rsa-oaep)
│       ├── RecipientKey       (X.509 cert / SKI / thumbprint — stable identity)
│       └── xenc:CipherData    (RSA-OAEP-wrapped KEK)
├── Body
│   └── Devices
│       └── Device 1..N        (systemTitle = primary identity, uppercase hex)
│           ├── ManufacturingInfo   (optional; shipment profile)
│           └── LogicalDevice 1..N  (logicalDeviceName, unique within Device)
│               ├── NetworkCredentials  (optional; suite-independent)
│               │   └── Credential type ∈ {EapPsk, Other}
│               └── DlmsKeySet 1..N     (securitySuite, clientId, name)
│                   │                   unique (securitySuite, clientId) per LogicalDevice
│                   └── Credential type ∈ {MasterKey,
│                                          GlobalUnicastEncryption,
│                                          GlobalAuthentication,
│                                          Other}
│                       ├── EncryptionMethod (kw-aes256-pad | none)
│                       ├── KekRef           (→ Header/Kek/@id; required for kw-aes256-pad)
│                       ├── xenc:CipherData  (AES-key-wrapped key)
│                       ├── KeyCheckValue    (optional)
│                       └── GeneratedAt       (optional)
└── ds:Signature        (optional, enveloped, covers whole document)
```

## Design decisions and rationale

### Two-layer key protection (RSA-OAEP over a KEK over AES key wrap)

Each device key is AES-key-wrapped under a symmetric **key-encryption key
(KEK)**; the KEK is in turn RSA-OAEP-wrapped to the recipient's public key. The
recipient does one RSA operation to recover the KEK, then fast symmetric
unwraps for every device key. For a large batch this is the difference between
thousands of RSA operations and one. This mirrors the proven structure of
existing proprietary files.

### One KEK per recipient — no more

The schema allows multiple `Kek` elements, but the **invariant is one KEK per
distinct recipient key pair**. A single-recipient file has exactly one KEK.
Multiple KEKs are meaningful only when a batch is split across multiple
recipients (each with their own RSA key), where they genuinely scope exposure.
Multiple KEKs all wrapped to the same recipient add structure without adding
security and should be avoided.

### Authenticated key wrap only: `kw-aes256-pad`

Key material is always wrapped with **AES-256 Key Wrap with Padding (RFC 5649)**
and nothing else. RFC 5649 is a strict superset of the original RFC 3394 AES Key
Wrap: it accepts key material of any byte length, making it fool-proof for all
credential types including `Other` credentials of non-standard length. For
standard DLMS key types (MasterKey, GUEK, GAK, EapPsk), which are 128-bit or
256-bit, RFC 5649 and RFC 3394 provide the same security properties.

AES key wrap is purpose-built for wrapping keys: it is deterministic, needs no
IV, and carries a built-in integrity check, so a bad unwrap is detected rather
than silently producing a corrupted key. Legacy CBC (used by the files this
format replaces) provides no integrity. AES-GCM was deliberately *not* offered
as an alternative: it is general-purpose AEAD that requires a unique IV per
operation, and IV reuse is catastrophic — an unnecessary footgun when the
payload is always a short, high-entropy key. One method means no negotiation,
no downgrade surface, and no IV field.

### RSA-OAEP for the KEK, never PKCS#1 v1.5

KEKs are wrapped with `rsa-oaep-mgf1p` or (preferred for new files) the XMLEnc
1.1 `rsa-oaep` URI. The legacy `rsa-1_5` padding seen in some existing
shipment files is vulnerable to padding-oracle attacks and is not permitted.

**SHA-1 note for `rsa-oaep-mgf1p`.** The XMLEnc 1.0 URI
`http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p` fixes the digest and mask
generation function to SHA-1.  SHA-1 here applies only to the OAEP masking
computation on a random 256-bit (or larger) AES key — not to a hash of
attacker-controlled plaintext — so the practical risk is lower than a typical
SHA-1 collision scenario.  However, organisations with a formal SHA-1
prohibition policy should use the XMLEnc 1.1 URI
`http://www.w3.org/2009/xmlenc11#rsa-oaep` with
`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha256"/>`
and a matching `<xenc11:MGF Algorithm="…#mgf1sha256"/>` child element.

### KEK identity is a stable cryptographic reference

A recipient holding many private keys must know which one unwraps a given KEK.
`RecipientKey` therefore carries an X.509 certificate, a SubjectKeyIdentifier,
or a certificate thumbprint — never a free-text magic string. A `KeyName` may
accompany these as a human label but cannot be the sole identifier.  This is
enforced by the Schematron rules.

### Device identity: COSEM system title (primary) + logical device name

A meter is identified by its **COSEM system title** (8 octets, **uppercase**
hex: 3-octet FLAG manufacturer id + serial), which is globally unique by
construction and is the key used for all in-file references and the future
logistics section. Uppercase is mandatory so that string-equality comparisons
(schema uniqueness checks, importer duplicate detection) are unambiguous.
Importers SHOULD normalize incoming titles to uppercase before comparison.

The **logical device name** identifies each COSEM logical device within the
meter. Logical device names are unique within their parent `Device` (enforced
by schema). Keys are scoped to a logical device, so the nesting is
`Device → LogicalDevice → keys`.

### Suite-scoped keys vs suite-independent network secrets

DLMS application-layer keys (master key, GUEK, GAK) depend on the **security
suite** (0/1 symmetric, 2 ECC), so they live inside a `DlmsKeySet` that carries
`securitySuite` as a structured attribute — not encoded into the key's name as
some proprietary files do. The **EAP-PSK** is a G3-PLC network-layer secret with
no relationship to the DLMS suite, so it sits in a sibling `NetworkCredentials`
block, not inside a suite-scoped set. `NetworkCredentials` is optional because
not every meter has a PSK.

Credential placement is normative (enforced by Schematron):

| Container | Allowed types |
|-----------|---------------|
| `NetworkCredentials` | `EapPsk`, `Other` |
| `DlmsKeySet` | `MasterKey`, `GlobalUnicastEncryption`, `GlobalAuthentication`, `Other` |

### `clientId` is the key-set grouping key

This format is opinionated that a security setup is **not** shared across
associations, so a single COSEM `clientId` faithfully identifies a key set. An
optional `name` ("management", "installer") is descriptive only. This avoids the
proprietary practice of mangling role names into key identifiers.

The schema enforces uniqueness of `(securitySuite, clientId)` pairs within a
logical device, so each key set has an unambiguous import target.

### Opinionated, minimal v1 vocabulary

The credential `type` enumeration is intentionally small:
`MasterKey`, `GlobalUnicastEncryption`, `GlobalAuthentication`, `EapPsk`, and an
`Other` escape hatch (which requires a companion `name`). These cover what real
shipment files actually carry for normal operation. Additional standardized
types (GBEK, HLS/LLS secrets, ECC private keys, certificates) are expected to
return in later schema versions. The `Other` hatch lets a vendor ship a
non-standard credential today without forking the schema.

### No version numbers — `GeneratedAt` instead

Keys rotate, but the format carries no key-version counter; a file holds the
latest known key. To prevent silently overwriting a newer key with an older one,
each credential may carry an optional `GeneratedAt` timestamp giving importers a
"don't go backwards" ordering signal. The file also carries a top-level
`createdAt` and a unique `id` for freshness and duplicate-import detection.

### Key check value

Each credential may carry a `KeyCheckValue` so an importer can confirm a correct
unwrap (and that it is loading the right key into the right slot) **without
exposing the key** — convention: AES-encrypt an all-zero block under the
unwrapped key, keep the leading octets.

### Plaintext keys: a per-key reality, gated by the header

Production files never contain plaintext keys. For sample/lab meters the header
flag `allowPlaintextKeys="true"` is an **acceptance gate**: a production importer
should reject any file that sets it. Whether a *given* key is plaintext is stated
per-credential by its `EncryptionMethod` (`none`), never by the flag alone — so
one misconfigured flag cannot silently strip protection from a whole batch.

### Optional whole-document signature

Signing is optional. When present, the `ds:Signature` is **enveloped** and
covers the entire `ShipmentFile` (matching the requirement to sign the full
file), using **Canonical XML 1.1** for canonicalization. Canonicalization is
what normalizes whitespace, so producers should emit no insignificant
whitespace and consumers must not depend on it. An unsigned file relies on the
authenticity of its transport channel; consumers should enforce a local policy
on whether unsigned files are acceptable.

#### Signed profile requirements

Implementors adding signature support must follow these requirements to avoid
the well-documented XML Signature pitfalls (wrapping attacks, partial signing,
algorithm confusion):

| Parameter | Required value |
|-----------|---------------|
| CanonicalizationMethod | Canonical XML 1.1 (`http://www.w3.org/2006/12/xml-c14n11`) |
| SignatureMethod | RSA-SHA256 or ECDSA-SHA256 minimum |
| DigestMethod | SHA-256 minimum |
| Reference URI | `""` (document root) |
| Transforms | Enveloped signature transform only (`http://www.w3.org/2000/09/xmldsig#enveloped-signature`) |

> **Reference URI note.** Use `URI=""` (empty string, resolves to the document
> root) rather than `URI="#<uuid>"`. The `@id` attribute is typed as a UUID
> string, not as `xs:ID`, and UUID values begin with a digit which makes them
> invalid NCNames. Fragment resolution via `#<uuid>` is therefore unreliable
> across XML Signature implementations. `URI=""` combined with the enveloped
> signature transform is the well-tested, portable way to sign the whole
> document.

Verifiers MUST:
* Check that the `Reference` URI resolves to the root `ShipmentFile` element
  (not a subset). The Schematron advisory rule assists producers at
  file-creation time but does not substitute for verifier-side checks.
* Validate the signer certificate chain against a trusted root, check
  revocation status, and enforce a local certificate policy.
* Reject any file whose signature does not cover the entire document.

### XML hygiene

* UTF-8, no BOM.
* `elementFormDefault="qualified"`; elements `PascalCase`, attributes
  `lowerCamelCase`.
* Schema version is carried in the namespace URI **and** mirrored in
  `@schemaVersion`.
* Referential integrity is enforced by the schema: every `KekRef/@kek` must
  resolve to a `Kek/@id` (`xs:keyref`), device system titles are unique within
  the file, logical device names are unique within a device, and
  `(securitySuite, clientId)` pairs are unique within a logical device
  (`xs:unique`).
* Forward compatibility via `Extension` elements accepting `##other`
  namespaces with `processContents="lax"` — vendors extend without breaking
  validation.
* **Versioning policy: additive only.** A new schema version may add credential
  types, algorithm URIs, or elements; it must never remove an existing
  algorithm or type, so newer producers stay readable by older-aware consumers
  wherever possible.

## Processing rules for importers

* **Partial failure:** reject a single malformed `Device` and continue importing
  the remaining devices; do not fail the whole file for one bad record.
  Atomicity is at the `DlmsKeySet` level: either all credentials in a key set
  are imported successfully, or none of them are. A half-imported key set
  (e.g. MasterKey written but GUEK failed) is a dangerous half-state; importers
  must roll back any keys already stored for that key set on error. Log the
  failed device system title, logical device name, security suite, and client id.
* **Unwrap order:** recover the KEK named by each `KekRef` (one RSA-OAEP
  operation per KEK), then AES-key-unwrap each credential.
* **Verify before store:** check each `KeyCheckValue` after unwrap; honor
  `GeneratedAt` to avoid downgrading a key.
* **Policy gates:** enforce signature policy and the `allowPlaintextKeys` gate
  per local rules before trusting any key material.

## Status

Draft `2026-05`. The schema and example in this package validate against each
other (including keyref and uniqueness constraints) and pass the Schematron
conformance rules. The XML-Signature and XML-Encryption stubs are deliberately
minimal; substitute the official W3C schemas for production signature
validation.
