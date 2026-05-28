<?xml version="1.0" encoding="UTF-8"?>
<!--
  ISO Schematron conformance rules for the Open DLMS/COSEM Shipment File
  Format, version 2026-05.

  These rules enforce security and structural constraints that XSD 1.0
  cannot express.  A file that passes both the XSD and this Schematron
  is "conformance-valid"; a file that passes only the XSD is
  "schema-valid" but NOT production-safe.

  Run with any ISO Schematron processor, for example:
    - schxslt (Java):
        java -jar schxslt-cli.jar -s dlms-shipment.sch -i example-shipment.xml
    - Python lxml:
        python -c "
          from lxml import etree, isoschematron
          sch = isoschematron.Schematron(etree.parse('dlms-shipment.sch'), store_report=True)
          doc = etree.parse('example-shipment.xml')
          ok = sch.validate(doc); print('OK' if ok else sch.validation_report)
        "
-->
<sch:schema xmlns:sch="http://purl.oclc.org/dsdl/schematron"
            xmlns:tns="https://open-metering.org/schemas/dlms-shipment-file/2026-05"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            queryBinding="xslt">

  <sch:title>DLMS Shipment File conformance rules (2026-05)</sch:title>

  <sch:ns prefix="tns" uri="https://open-metering.org/schemas/dlms-shipment-file/2026-05"/>
  <sch:ns prefix="ds"  uri="http://www.w3.org/2000/09/xmldsig#"/>

  <!-- ================================================================== -->
  <!-- 1. RecipientKey must carry a stable cryptographic identifier        -->
  <!-- ================================================================== -->
  <!--
    A KeyName alone is a free-text label that cannot be used to
    unambiguously select a private key from a key store.  At least one
    of X509Certificate, SubjectKeyIdentifier, or CertificateThumbprint
    must be present so that an importer can determine which key to use.
  -->
  <sch:pattern id="recipient-key-identity">
    <sch:rule context="tns:RecipientKey">
      <sch:assert test="tns:X509Certificate or tns:SubjectKeyIdentifier or tns:CertificateThumbprint">
        RecipientKey must contain at least one of X509Certificate,
        SubjectKeyIdentifier, or CertificateThumbprint.  A KeyName alone
        is not a valid recipient identity.
      </sch:assert>
    </sch:rule>
  </sch:pattern>

  <!-- ================================================================== -->
  <!-- 2. Plaintext key material requires the file-level gate             -->
  <!-- ================================================================== -->
  <!--
    The allowPlaintextKeys attribute is an acceptance gate for the whole
    file.  Using EncryptionMethod "none" without setting that gate to
    "true" on the root element is a misconfiguration that would silently
    deliver unprotected key material to an importer that enforces the
    gate.
  -->
  <sch:pattern id="plaintext-gate">
    <sch:rule context="tns:Credential/tns:EncryptionMethod[
        @algorithm = 'https://open-metering.org/schemas/dlms-shipment-file/2026-05#none']">
      <sch:assert test="ancestor::tns:ShipmentFile[@allowPlaintextKeys = 'true']">
        EncryptionMethod "none" requires allowPlaintextKeys="true" on
        the root ShipmentFile element.  Production importers reject files
        with allowPlaintextKeys="true", so plaintext keys are for
        sample/lab meters only.
      </sch:assert>
    </sch:rule>
  </sch:pattern>

  <!-- ================================================================== -->
  <!-- 3. kw-aes256-pad requires a KekRef                                 -->
  <!-- ================================================================== -->
  <!--
    The XSD marks KekRef as optional (it is absent for plaintext keys),
    but when the wrapping algorithm is kw-aes256-pad the importer needs a
    KekRef to know which KEK to use for unwrapping.  Omitting it makes
    the credential unrecoverable.
  -->
  <sch:pattern id="kw-aes256-pad-requires-kekref">
    <sch:rule context="tns:Credential/tns:EncryptionMethod[
        @algorithm = 'http://www.w3.org/2009/xmlenc11#kw-aes-256-pad']">
      <sch:assert test="../tns:KekRef">
        A Credential with EncryptionMethod kw-aes256-pad must have a sibling
        KekRef element that names the KEK used for wrapping.
      </sch:assert>
    </sch:rule>
  </sch:pattern>

  <!-- ================================================================== -->
  <!-- 4. Credential type="Other" requires a non-empty @name              -->
  <!-- ================================================================== -->
  <!--
    "Other" is an escape hatch for non-standard credential types.  Its
    value comes from the companion @name attribute, which lets importers
    dispatch on a vendor-specific label.  Without @name the credential
    type is meaningless.
  -->
  <sch:pattern id="other-credential-name">
    <sch:rule context="tns:Credential[@type = 'Other']">
      <sch:assert test="normalize-space(@name) != ''">
        Credential type="Other" requires a non-empty @name attribute
        that identifies the non-standard credential kind.
      </sch:assert>
    </sch:rule>
  </sch:pattern>

  <!-- ================================================================== -->
  <!-- 5. Credential placement: NetworkCredentials                        -->
  <!-- ================================================================== -->
  <!--
    NetworkCredentials holds suite-independent network-layer secrets.
    In v1 the only valid type is EapPsk (G3-PLC PSK) or Other (for
    non-standard network secrets).  DLMS application-layer key types
    (MasterKey, GlobalUnicastEncryption, GlobalAuthentication) must not
    appear here.
  -->
  <sch:pattern id="network-credential-types">
    <sch:rule context="tns:NetworkCredentials/tns:Credential">
      <sch:assert test="@type = 'EapPsk' or @type = 'Other'">
        NetworkCredentials may only contain credentials of type EapPsk
        or Other.  Found type "<sch:value-of select="@type"/>".
        DLMS application-layer keys belong in DlmsKeySet.
      </sch:assert>
    </sch:rule>
  </sch:pattern>

  <!-- ================================================================== -->
  <!-- 6. Credential placement: DlmsKeySet                               -->
  <!-- ================================================================== -->
  <!--
    DlmsKeySet holds suite-scoped DLMS application-layer keys.  EapPsk
    is a network-layer secret that has no relationship to the DLMS
    security suite and must not appear here.
  -->
  <sch:pattern id="dlms-keyset-credential-types">
    <sch:rule context="tns:DlmsKeySet/tns:Credential">
      <sch:assert test="@type != 'EapPsk'">
        DlmsKeySet must not contain EapPsk credentials.  EapPsk is a
        suite-independent network secret and belongs in
        NetworkCredentials.
      </sch:assert>
    </sch:rule>
  </sch:pattern>

  <!-- ================================================================== -->
  <!-- 7. Signature reference covers the whole document (advisory)        -->
  <!-- ================================================================== -->
  <!--
    An enveloped XML signature must sign the entire ShipmentFile.  A
    Reference with a fragment URI pointing to an interior element would
    leave the rest of the document unsigned and open to tampering.
    The correct URI is "" (the document root) or "#<document-id>".
    This is an advisory check; it fires at file-creation time and helps
    producers catch partial-signing mistakes before distribution.
  -->
  <sch:pattern id="signature-root-reference">
    <sch:rule context="ds:Signature">
      <sch:assert test="
          ds:SignedInfo/ds:Reference[@URI = ''] or
          ds:SignedInfo/ds:Reference[@URI = concat('#', /tns:ShipmentFile/@id)]">
        The ds:Signature must contain a Reference whose URI is either ""
        (the document root) or "#&lt;document-id&gt;" so that the entire
        ShipmentFile is covered.  A signature that covers only part of
        the document does not protect the whole file.
      </sch:assert>
    </sch:rule>
  </sch:pattern>

</sch:schema>
