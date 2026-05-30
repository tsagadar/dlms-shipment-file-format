"""Shared low-level crypto and XML primitives for the shipment file format.

Holds the namespace / algorithm constants and canonicalization used by both the
write side (``generator``) and the read side (``validation`` / ``importer``),
plus the read-side inverses of the build code: signature verification and key
unwrapping.
"""

from __future__ import annotations

import base64
import copy
import hashlib
from io import BytesIO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap_with_padding
from lxml import etree

NS = "https://open-metering.org/schemas/dlms-shipment-file/2026-05"
NS_XENC = "http://www.w3.org/2001/04/xmlenc#"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"

ALGO_RSA_OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
ALGO_KW_AES256_PAD = "http://www.w3.org/2009/xmlenc11#kw-aes-256-pad"
ALGO_NONE = f"{NS}#none"
ALGO_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
ALGO_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
ALGO_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
ALGO_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"


def c14n(element: etree._Element) -> bytes:
    buf = BytesIO()
    etree.ElementTree(element).write_c14n(buf, exclusive=False, with_comments=False)
    return buf.getvalue()


def verify_signature(root: etree._Element, public_key: RSAPublicKey) -> None:
    """Verify the enveloped ds:Signature on ``root``; raise on any mismatch.

    Inverse of ``generator.ShipmentFileBuilder._apply_signature``: recompute the
    document digest over the C14N of the document with the Signature removed
    (the enveloped-signature transform), then verify the RSA-SHA256 signature
    over the C14N of SignedInfo.
    """
    sig_el = root.find(f"{{{NS_DS}}}Signature")
    if sig_el is None:
        raise ValueError("no ds:Signature element")
    signed_info = sig_el.find(f"{{{NS_DS}}}SignedInfo")
    if signed_info is None:
        raise ValueError("ds:Signature has no SignedInfo")

    digest_b64 = signed_info.findtext(f".//{{{NS_DS}}}DigestValue")
    sig_b64 = sig_el.findtext(f"{{{NS_DS}}}SignatureValue")
    if not digest_b64 or not sig_b64:
        raise ValueError("ds:Signature missing DigestValue or SignatureValue")

    # Document digest: C14N of the document with the Signature element removed.
    doc_copy = copy.deepcopy(root)
    doc_copy.remove(doc_copy.find(f"{{{NS_DS}}}Signature"))
    if hashlib.sha256(c14n(doc_copy)).digest() != base64.b64decode(digest_b64.strip()):
        raise ValueError("document digest does not match DigestValue")

    # Verify the signature over the C14N of SignedInfo (from the in-tree element
    # so it keeps its inherited namespace context).  Raises InvalidSignature on
    # mismatch.
    public_key.verify(
        base64.b64decode(sig_b64.strip()),
        c14n(signed_info),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def unwrap_kek(wrapped: bytes, private_key: RSAPrivateKey) -> bytes:
    """Unwrap a KEK with the recipient's RSA private key (RSA-OAEP/SHA-1)."""
    return private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )


def unwrap_credential(kek: bytes, wrapped: bytes) -> bytes:
    """Unwrap a credential key with the KEK (AES-256 key unwrap with padding)."""
    return aes_key_unwrap_with_padding(kek, wrapped)


def cipher_value(el: etree._Element) -> bytes:
    """Decode the base64 xenc:CipherValue carried under ``el``."""
    text = el.findtext(f"{{{NS_XENC}}}CipherData/{{{NS_XENC}}}CipherValue")
    if not text:
        raise ValueError("missing xenc:CipherValue")
    return base64.b64decode(text.strip())


def unwrap_all_keks(root: etree._Element, private_key: RSAPrivateKey) -> dict[str, bytes]:
    """Unwrap every Header/Kek, keyed by its ``id``."""
    keks: dict[str, bytes] = {}
    for kek_el in root.findall(f".//{{{NS}}}Kek"):
        kek_id = kek_el.get("id")
        if kek_id is None:
            continue
        keks[kek_id] = unwrap_kek(cipher_value(kek_el), private_key)
    return keks
