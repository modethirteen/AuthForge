<?php declare(strict_types=1);
/**
 * AuthForge
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace modethirteen\AuthForge\Tests\ServiceProvider\Saml\Document;

use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentSignatureValidationException;
use modethirteen\AuthForge\Tests\ServiceProvider\Saml\AbstractSamlTestCase;
use modethirteen\Crypto\Exception\CryptoKeyCannotParseCryptoKeyTextException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryCannotConstructCryptoKeyException;
use modethirteen\Crypto\ImportCryptoKeyPairFactory;

class validateSignature_Test extends AbstractSamlTestCase {

    const SIGNATURE_KEY = <<<TEXT
-----BEGIN RSA PRIVATE KEY-----
MIICXwIBAAKBgQCnCWkWWY/HjFe6y+6HWJ2QW2U6MTDoYDDZYmF63qDiLVqNM2Us
COGMywL+eDAVTCKpPLKwj/4qf9sROXGLZXKDCg0bLrQEvlsPWN8t6MxWqLcG+ZIG
FevS5IOs2WhTPHVwy4HVmgefNEbwPEhe3KXL3V9lm+DwhmA34f9aajo+jwIDAQAB
AoGBAAjU1YqJ97EcOXM13wmm5MXCH0sBWM2gcFS9/9toM+dhcH0wr3OxkINKJIFh
x2EI4nhCLkxpgI2srt9tQxSUq4YuNlkpAOJ2IN7NPzctPUsG6+ry4R+Wpe4CPUx9
aIMufokHuO/RDQqEmUjls8sTRt42MAZXUfsnZXkVx+GKv4MBAkEA2qMSNWPxM60O
cpG5CVdRWsgwPwYMlscaeAIO3xfVRTiQnIFZ0UgD4Lk/boNeQ6GsLhqMlpEV5f7g
NfH66UPegQJBAMOU7ss1Ez7HWZ9y4hw6Hgn3RVg0dtEdIs0MBHkrSTa5Gx9EfR1t
aIW71H1V06wn2K4kq47bFf/c6TNCGclvtQ8CQQC1UPNyz5Vis6v9m5gGhSF01fwc
6BlcmXX7/Ej0/sDhjQ1wnV0tUDnXDgnqzotILzWpbl8VJvEwMfUjB7B77ssBAkEA
lpTiTb4tdRZTIHp5MDZmzlF9KG4sVNBT7P8lqozzL5jREv/OPIvx/5UgAufDszZy
k5FULQbtJzPUsExiQj8pbQJBALZIJRUTh7H4Z/xJ4W/p38qKRRxctGaw8NjNAX0H
ABzMxrayevhKdEYa7pF+kYkgdK4smw35VWAYM5ExisqYW54=
-----END RSA PRIVATE KEY-----
TEXT;

    const SIGNATURE_X509 = <<<TEXT
-----BEGIN CERTIFICATE-----
MIIDCTCCAnKgAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMRQwEgYDVQQDEwtjYXBy
aXphLmNvbTELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQH
EwpCbGFja3NidXJnMRAwDgYDVQQKEwdTYW1saW5nMRAwDgYDVQQLEwdTYW1saW5n
MB4XDTE5MDIyMzAwNDE0N1oXDTIwMDIyMzAwNDE0N1owbzEUMBIGA1UEAxMLY2Fw
cml6YS5jb20xCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UE
BxMKQmxhY2tzYnVyZzEQMA4GA1UEChMHU2FtbGluZzEQMA4GA1UECxMHU2FtbGlu
ZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApwlpFlmPx4xXusvuh1idkFtl
OjEw6GAw2WJhet6g4i1ajTNlLAjhjMsC/ngwFUwiqTyysI/+Kn/bETlxi2VygwoN
Gy60BL5bD1jfLejMVqi3BvmSBhXr0uSDrNloUzx1cMuB1ZoHnzRG8DxIXtyly91f
ZZvg8IZgN+H/Wmo6Po8CAwEAAaOBtDCBsTAMBgNVHRMEBTADAQH/MAsGA1UdDwQE
AwIC9DA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggr
BgEFBQcDBAYIKwYBBQUHAwgwEQYJYIZIAYb4QgEBBAQDAgD3MCUGA1UdEQQeMByG
Gmh0dHA6Ly9jYXByaXphLmNvbS9zYW1saW5nMB0GA1UdDgQWBBSC2h+3WPYc9aqF
afnsIavOddfRHTANBgkqhkiG9w0BAQUFAAOBgQAxT0KVDSuCRt827ciABzXJV0sy
E1FtVQDSspRrDfJInYVtAZUhU5hX1d2jXFBpAOOYrd3qj9vCiXFBtCmu2SQ5min1
LOD/z5Bd8N4SZAiZYo8o7Px9x46R3DNIIIu3O5TjUcElBB/6Gf36yQbnbJqRVfLG
+e9UUyoEfUNDjPzcSw==
-----END CERTIFICATE-----
TEXT;

    /**
     * @note (modethirteen, 20200110): messages were signed by a reputable third party using the verification keys loaded in this test case
     * @return array
     */
    public static function message_Provider() : array {
        return [
            'AuthnRequest' => [
                <<<XML
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfx9b096036-d71d-e0d5-de55-ead838525c3e" Version="2.0" ProviderName="SP test" IssueInstant="2014-07-16T23:52:45Z" Destination="http://idp.example.com/SSOService.php" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="http://sp.example.com/demo1/index.php?acs">
  <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx9b096036-d71d-e0d5-de55-ead838525c3e"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>qjtVJWUFPmV4oN19Lqs7QKdzFhw=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Qo8WM8F5RuHjAaUz2aRUYs0mcDXi4F8yz6W0VxLZVUw8C12cG7MCeELjiMv6/5lYmxmABHp7EMuX99APmwpXp/mtuseJXAb2UM+1QNP6FQSjz0zi9fyVzpjpOOiNYDd7mZcjSl8PkM0JfE6SqBrxdtce7PgxL9cVYRhYKH9Rw64=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDCTCCAnKgAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMRQwEgYDVQQDEwtjYXByaXphLmNvbTELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQHEwpCbGFja3NidXJnMRAwDgYDVQQKEwdTYW1saW5nMRAwDgYDVQQLEwdTYW1saW5nMB4XDTE5MDIyMzAwNDE0N1oXDTIwMDIyMzAwNDE0N1owbzEUMBIGA1UEAxMLY2Fwcml6YS5jb20xCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tzYnVyZzEQMA4GA1UEChMHU2FtbGluZzEQMA4GA1UECxMHU2FtbGluZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApwlpFlmPx4xXusvuh1idkFtlOjEw6GAw2WJhet6g4i1ajTNlLAjhjMsC/ngwFUwiqTyysI/+Kn/bETlxi2VygwoNGy60BL5bD1jfLejMVqi3BvmSBhXr0uSDrNloUzx1cMuB1ZoHnzRG8DxIXtyly91fZZvg8IZgN+H/Wmo6Po8CAwEAAaOBtDCBsTAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIC9DA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgwEQYJYIZIAYb4QgEBBAQDAgD3MCUGA1UdEQQeMByGGmh0dHA6Ly9jYXByaXphLmNvbS9zYW1saW5nMB0GA1UdDgQWBBSC2h+3WPYc9aqFafnsIavOddfRHTANBgkqhkiG9w0BAQUFAAOBgQAxT0KVDSuCRt827ciABzXJV0syE1FtVQDSspRrDfJInYVtAZUhU5hX1d2jXFBpAOOYrd3qj9vCiXFBtCmu2SQ5min1LOD/z5Bd8N4SZAiZYo8o7Px9x46R3DNIIIu3O5TjUcElBB/6Gf36yQbnbJqRVfLG+e9UUyoEfUNDjPzcSw==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
XML
            ],
            'Signed Response, Unsigned Assertion' => [
                <<<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfxd959abca-486b-cd4a-1869-9e888634f241" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfxd959abca-486b-cd4a-1869-9e888634f241"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>hB3wUQwVAqYuG7ulMPPYWpYRO3M=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>f/EFlNev9+GmoYG32VC35gE2pZRox5y5iVK34Uky+sg8ekTgTrZWIowPycN5hqPejKuYtE0zztIyyRpdB2eIkKuqUfOFU/mP95ZVm8ww/DB75zG3FgBcJmLGBx5Yg9x0mi5MuGX8EzcpucuZJurKa3rrj847jX5emW6KKyZx4s8=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDCTCCAnKgAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMRQwEgYDVQQDEwtjYXByaXphLmNvbTELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQHEwpCbGFja3NidXJnMRAwDgYDVQQKEwdTYW1saW5nMRAwDgYDVQQLEwdTYW1saW5nMB4XDTE5MDIyMzAwNDE0N1oXDTIwMDIyMzAwNDE0N1owbzEUMBIGA1UEAxMLY2Fwcml6YS5jb20xCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tzYnVyZzEQMA4GA1UEChMHU2FtbGluZzEQMA4GA1UECxMHU2FtbGluZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApwlpFlmPx4xXusvuh1idkFtlOjEw6GAw2WJhet6g4i1ajTNlLAjhjMsC/ngwFUwiqTyysI/+Kn/bETlxi2VygwoNGy60BL5bD1jfLejMVqi3BvmSBhXr0uSDrNloUzx1cMuB1ZoHnzRG8DxIXtyly91fZZvg8IZgN+H/Wmo6Po8CAwEAAaOBtDCBsTAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIC9DA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgwEQYJYIZIAYb4QgEBBAQDAgD3MCUGA1UdEQQeMByGGmh0dHA6Ly9jYXByaXphLmNvbS9zYW1saW5nMB0GA1UdDgQWBBSC2h+3WPYc9aqFafnsIavOddfRHTANBgkqhkiG9w0BAQUFAAOBgQAxT0KVDSuCRt827ciABzXJV0syE1FtVQDSspRrDfJInYVtAZUhU5hX1d2jXFBpAOOYrd3qj9vCiXFBtCmu2SQ5min1LOD/z5Bd8N4SZAiZYo8o7Px9x46R3DNIIIu3O5TjUcElBB/6Gf36yQbnbJqRVfLG+e9UUyoEfUNDjPzcSw==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
    <saml:Subject>
      <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
XML
            ],
            'Signed Response, Signed Assertion' => [
                <<<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfx8e20ab2e-2ec9-9976-be79-57fab684b806" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx8e20ab2e-2ec9-9976-be79-57fab684b806"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>k/wlllGe/sEIquEc/VRjrH1dO7I=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>CTpsJYs5ZGvv91kBrmXI8rWWFs0+W8dv7ln11j5Jf1hY2kBKpvMi/P1GqKD15RqRfjUgoqtfQa0dQ2EfGtCdPDLnhNC1qTl30LbupYZL9UXU+LP6ncOBlnNfjJwKzuzULCFi3R8UuJKKwI13umNPD1yz5yPnGU+Uhji62UUUR7k=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDCTCCAnKgAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMRQwEgYDVQQDEwtjYXByaXphLmNvbTELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQHEwpCbGFja3NidXJnMRAwDgYDVQQKEwdTYW1saW5nMRAwDgYDVQQLEwdTYW1saW5nMB4XDTE5MDIyMzAwNDE0N1oXDTIwMDIyMzAwNDE0N1owbzEUMBIGA1UEAxMLY2Fwcml6YS5jb20xCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tzYnVyZzEQMA4GA1UEChMHU2FtbGluZzEQMA4GA1UECxMHU2FtbGluZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApwlpFlmPx4xXusvuh1idkFtlOjEw6GAw2WJhet6g4i1ajTNlLAjhjMsC/ngwFUwiqTyysI/+Kn/bETlxi2VygwoNGy60BL5bD1jfLejMVqi3BvmSBhXr0uSDrNloUzx1cMuB1ZoHnzRG8DxIXtyly91fZZvg8IZgN+H/Wmo6Po8CAwEAAaOBtDCBsTAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIC9DA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgwEQYJYIZIAYb4QgEBBAQDAgD3MCUGA1UdEQQeMByGGmh0dHA6Ly9jYXByaXphLmNvbS9zYW1saW5nMB0GA1UdDgQWBBSC2h+3WPYc9aqFafnsIavOddfRHTANBgkqhkiG9w0BAQUFAAOBgQAxT0KVDSuCRt827ciABzXJV0syE1FtVQDSspRrDfJInYVtAZUhU5hX1d2jXFBpAOOYrd3qj9vCiXFBtCmu2SQ5min1LOD/z5Bd8N4SZAiZYo8o7Px9x46R3DNIIIu3O5TjUcElBB/6Gf36yQbnbJqRVfLG+e9UUyoEfUNDjPzcSw==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="pfx944b36a6-7bf4-a2f7-7e35-9f5ef568cf64" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx944b36a6-7bf4-a2f7-7e35-9f5ef568cf64"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>Z2fKJQ006w+E3Jjkg1jB3otZTpU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>ZK7qkMlllsr3qqoCH3CSvGzkBjmhb1mkYjwM2yKoN4wuJG8lmpc7rCPzxvI0bV88IwElP5jJrs2xOKSuZWqwoLh7HyUA8G5UlEkLGVPRLi7Tqlm9e3eFbyuIPhvDShIcanZot1sw7z07ftNQOPqGqpYCmAThq71CTdDK97/sY3Q=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDCTCCAnKgAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMRQwEgYDVQQDEwtjYXByaXphLmNvbTELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQHEwpCbGFja3NidXJnMRAwDgYDVQQKEwdTYW1saW5nMRAwDgYDVQQLEwdTYW1saW5nMB4XDTE5MDIyMzAwNDE0N1oXDTIwMDIyMzAwNDE0N1owbzEUMBIGA1UEAxMLY2Fwcml6YS5jb20xCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tzYnVyZzEQMA4GA1UEChMHU2FtbGluZzEQMA4GA1UECxMHU2FtbGluZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApwlpFlmPx4xXusvuh1idkFtlOjEw6GAw2WJhet6g4i1ajTNlLAjhjMsC/ngwFUwiqTyysI/+Kn/bETlxi2VygwoNGy60BL5bD1jfLejMVqi3BvmSBhXr0uSDrNloUzx1cMuB1ZoHnzRG8DxIXtyly91fZZvg8IZgN+H/Wmo6Po8CAwEAAaOBtDCBsTAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIC9DA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgwEQYJYIZIAYb4QgEBBAQDAgD3MCUGA1UdEQQeMByGGmh0dHA6Ly9jYXByaXphLmNvbS9zYW1saW5nMB0GA1UdDgQWBBSC2h+3WPYc9aqFafnsIavOddfRHTANBgkqhkiG9w0BAQUFAAOBgQAxT0KVDSuCRt827ciABzXJV0syE1FtVQDSspRrDfJInYVtAZUhU5hX1d2jXFBpAOOYrd3qj9vCiXFBtCmu2SQ5min1LOD/z5Bd8N4SZAiZYo8o7Px9x46R3DNIIIu3O5TjUcElBB/6Gf36yQbnbJqRVfLG+e9UUyoEfUNDjPzcSw==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
    <saml:Subject>
      <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
XML
            ],
            'Unsigned Response, Signed Assertion' => [
                <<<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="pfx03fdf894-3491-cad5-1295-909f24270ee0" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx03fdf894-3491-cad5-1295-909f24270ee0"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>tyHqp3H+neXcpTLUJIIoJ9fXfmo=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>axAkXbkejTaJBqCzKSW/Yzmb8VdfIBFUdtHFAkwNB/XyUti1IoXLgE8qgbLHKi5NqYm+nrVMRJD5LE2A1n/73hHwDitdDr1JQYzBnOVmpLGwFarWz/2kIuhuQjEKF18jKkv97whpSE56GeICNXyYVRsmSUZ2t5inFAw+WQcfz1I=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDCTCCAnKgAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMRQwEgYDVQQDEwtjYXByaXphLmNvbTELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQHEwpCbGFja3NidXJnMRAwDgYDVQQKEwdTYW1saW5nMRAwDgYDVQQLEwdTYW1saW5nMB4XDTE5MDIyMzAwNDE0N1oXDTIwMDIyMzAwNDE0N1owbzEUMBIGA1UEAxMLY2Fwcml6YS5jb20xCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tzYnVyZzEQMA4GA1UEChMHU2FtbGluZzEQMA4GA1UECxMHU2FtbGluZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApwlpFlmPx4xXusvuh1idkFtlOjEw6GAw2WJhet6g4i1ajTNlLAjhjMsC/ngwFUwiqTyysI/+Kn/bETlxi2VygwoNGy60BL5bD1jfLejMVqi3BvmSBhXr0uSDrNloUzx1cMuB1ZoHnzRG8DxIXtyly91fZZvg8IZgN+H/Wmo6Po8CAwEAAaOBtDCBsTAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIC9DA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgwEQYJYIZIAYb4QgEBBAQDAgD3MCUGA1UdEQQeMByGGmh0dHA6Ly9jYXByaXphLmNvbS9zYW1saW5nMB0GA1UdDgQWBBSC2h+3WPYc9aqFafnsIavOddfRHTANBgkqhkiG9w0BAQUFAAOBgQAxT0KVDSuCRt827ciABzXJV0syE1FtVQDSspRrDfJInYVtAZUhU5hX1d2jXFBpAOOYrd3qj9vCiXFBtCmu2SQ5min1LOD/z5Bd8N4SZAiZYo8o7Px9x46R3DNIIIu3O5TjUcElBB/6Gf36yQbnbJqRVfLG+e9UUyoEfUNDjPzcSw==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
    <saml:Subject>
      <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
XML
            ],
            'LogoutRequest' => [
                <<<XML
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfxfc9f5079-da43-9fc6-0e7d-c56f87039404" Version="2.0" IssueInstant="2014-07-18T01:13:06Z" Destination="http://idp.example.com/SingleLogoutService.php">
 <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfxfc9f5079-da43-9fc6-0e7d-c56f87039404"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>TQPPRIjJO9cX5x32qH/HQdoAHlo=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Z6+v+2O6N3aQzuBZtJcD2lkHTp7UHuoDNr2s5CGZiVxMwdMSQXcn6mwTdmTtS0HZgj401Hy9vFqM/opF+A5aLU61vSxSh2nYCnLSsD7VRNLaH+WOB58I9fYBpt8QXUkpCOZfcolvG6gthgimXbJ++cqAnawLghQMvgU4O8/0vuU=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDCTCCAnKgAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMRQwEgYDVQQDEwtjYXByaXphLmNvbTELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQHEwpCbGFja3NidXJnMRAwDgYDVQQKEwdTYW1saW5nMRAwDgYDVQQLEwdTYW1saW5nMB4XDTE5MDIyMzAwNDE0N1oXDTIwMDIyMzAwNDE0N1owbzEUMBIGA1UEAxMLY2Fwcml6YS5jb20xCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tzYnVyZzEQMA4GA1UEChMHU2FtbGluZzEQMA4GA1UECxMHU2FtbGluZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApwlpFlmPx4xXusvuh1idkFtlOjEw6GAw2WJhet6g4i1ajTNlLAjhjMsC/ngwFUwiqTyysI/+Kn/bETlxi2VygwoNGy60BL5bD1jfLejMVqi3BvmSBhXr0uSDrNloUzx1cMuB1ZoHnzRG8DxIXtyly91fZZvg8IZgN+H/Wmo6Po8CAwEAAaOBtDCBsTAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIC9DA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgwEQYJYIZIAYb4QgEBBAQDAgD3MCUGA1UdEQQeMByGGmh0dHA6Ly9jYXByaXphLmNvbS9zYW1saW5nMB0GA1UdDgQWBBSC2h+3WPYc9aqFafnsIavOddfRHTANBgkqhkiG9w0BAQUFAAOBgQAxT0KVDSuCRt827ciABzXJV0syE1FtVQDSspRrDfJInYVtAZUhU5hX1d2jXFBpAOOYrd3qj9vCiXFBtCmu2SQ5min1LOD/z5Bd8N4SZAiZYo8o7Px9x46R3DNIIIu3O5TjUcElBB/6Gf36yQbnbJqRVfLG+e9UUyoEfUNDjPzcSw==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7</saml:NameID>
</samlp:LogoutRequest>
XML
            ],
            'LogoutResponse' => [
                <<<XML
<?xml version="1.0"?>
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfx3f658716-414c-eb6d-2e2f-ab9d4a9eb56a" Version="2.0" IssueInstant="2014-07-18T01:13:06Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx3f658716-414c-eb6d-2e2f-ab9d4a9eb56a"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>8Z1ReQPHbzvjrUdME6fVGSHJ2UA=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>U471lyALNZUZ05Lx89647y9BBA2d67YqnJpuLOXlu9rJIQrgqSkkgrWoVwLRISJ2t+nkMynIp1E6qPXcvTHAl5mJ69BXXMQBggfJf+EnKphdtC1PsRk/8Q1VfURfyrBtipnFYhCvRr598ME2fufo6KNiOxbTZmuyMfuOYq2ZiRc=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDCTCCAnKgAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMRQwEgYDVQQDEwtjYXByaXphLmNvbTELMAkGA1UEBhMCVVMxETAPBgNVBAgTCFZpcmdpbmlhMRMwEQYDVQQHEwpCbGFja3NidXJnMRAwDgYDVQQKEwdTYW1saW5nMRAwDgYDVQQLEwdTYW1saW5nMB4XDTE5MDIyMzAwNDE0N1oXDTIwMDIyMzAwNDE0N1owbzEUMBIGA1UEAxMLY2Fwcml6YS5jb20xCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tzYnVyZzEQMA4GA1UEChMHU2FtbGluZzEQMA4GA1UECxMHU2FtbGluZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApwlpFlmPx4xXusvuh1idkFtlOjEw6GAw2WJhet6g4i1ajTNlLAjhjMsC/ngwFUwiqTyysI/+Kn/bETlxi2VygwoNGy60BL5bD1jfLejMVqi3BvmSBhXr0uSDrNloUzx1cMuB1ZoHnzRG8DxIXtyly91fZZvg8IZgN+H/Wmo6Po8CAwEAAaOBtDCBsTAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIC9DA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgwEQYJYIZIAYb4QgEBBAQDAgD3MCUGA1UdEQQeMByGGmh0dHA6Ly9jYXByaXphLmNvbS9zYW1saW5nMB0GA1UdDgQWBBSC2h+3WPYc9aqFafnsIavOddfRHTANBgkqhkiG9w0BAQUFAAOBgQAxT0KVDSuCRt827ciABzXJV0syE1FtVQDSspRrDfJInYVtAZUhU5hX1d2jXFBpAOOYrd3qj9vCiXFBtCmu2SQ5min1LOD/z5Bd8N4SZAiZYo8o7Px9x46R3DNIIIu3O5TjUcElBB/6Gf36yQbnbJqRVfLG+e9UUyoEfUNDjPzcSw==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:LogoutResponse>
XML
            ]
        ];
    }

    /**
     * @dataProvider message_Provider
     * @test
     * @param string $message
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     * @throws SamlDocumentSignatureValidationException
     */
    public function Can_validate_message(string $message) : void {

        // arrange
        $keys = (new ImportCryptoKeyPairFactory(self::SIGNATURE_KEY, self::SIGNATURE_X509))
            ->withDigestAlgorithm('sha1')
            ->newCryptoKeyPair();
        $document = static::newDocumentFactory()->newMessageDocument($message);

        // act
        $document->validateSignature($keys->getPublicKey());

        // assert
        static::addToAssertionCount(1);
    }
}
