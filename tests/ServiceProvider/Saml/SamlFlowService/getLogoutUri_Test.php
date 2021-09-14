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
namespace modethirteen\AuthForge\Tests\ServiceProvider\Saml\SamlFlowService;

use DateTimeImmutable;
use modethirteen\AuthForge\Common\Logger\ContextLoggerInterface;
use modethirteen\AuthForge\ServiceProvider\Saml\Document;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotGenerateSignatureException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentCannotWriteTextException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlFlowServiceException;
use modethirteen\AuthForge\ServiceProvider\Saml\Http\HttpMessageInterface;
use modethirteen\AuthForge\ServiceProvider\Saml\Http\SamlHttpMessageUri;
use modethirteen\AuthForge\ServiceProvider\Saml\SamlConfigurationInterface;
use modethirteen\AuthForge\ServiceProvider\Saml\SamlFlowService;
use modethirteen\AuthForge\ServiceProvider\Saml\SessionIndexRegistryInterface;
use modethirteen\AuthForge\Tests\ServiceProvider\Saml\AbstractSamlTestCase;
use modethirteen\Crypto\Exception\CryptoKeyCannotParseCryptoKeyTextException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryCannotConstructCryptoKeyException;
use modethirteen\Http\Exception\MalformedPathQueryFragmentException;
use modethirteen\Http\Exception\MalformedUriException;
use modethirteen\Http\XUri;
use modethirteen\TypeEx\StringDictionary;
use modethirteen\TypeEx\StringEx;
use Psr\EventDispatcher\EventDispatcherInterface;
use Ramsey\Uuid\UuidFactoryInterface;
use Ramsey\Uuid\UuidInterface;

class getLogoutUri_Test extends AbstractSamlTestCase {

    /**
     * @return array
     */
    public static function isLogoutRequestSignatureRequired_isNameIdEncryptionRequired_nameIdFormat_sessionIndex_expected_Provider() : array {
        return [
            'With signature and with NameID encryption and with NameID format and with session index' => [true, true, HttpMessageInterface::NAMEID_UNSPECIFIED, 'foo', <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:EncryptedID>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
      <dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
        <xenc:EncryptedKey>
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
          <xenc:CipherData>
            <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/dsig:KeyInfo/xenc:EncryptedKey/xenc:CipherData}}</xenc:CipherValue>
          </xenc:CipherData>
        </xenc:EncryptedKey>
      </dsig:KeyInfo>
      <xenc:CipherData>
        <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/xenc:CipherData}}</xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedData>
  </saml:EncryptedID>
  <samlp:SessionIndex>foo</samlp:SessionIndex>
</samlp:LogoutRequest>

XML
            ],
            'With signature and with NameID encryption and without NameID format and with session index' => [true, true, null, 'bar', <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:EncryptedID>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
      <dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
        <xenc:EncryptedKey>
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
          <xenc:CipherData>
            <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/dsig:KeyInfo/xenc:EncryptedKey/xenc:CipherData}}</xenc:CipherValue>
          </xenc:CipherData>
        </xenc:EncryptedKey>
      </dsig:KeyInfo>
      <xenc:CipherData>
        <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/xenc:CipherData}}</xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedData>
  </saml:EncryptedID>
  <samlp:SessionIndex>bar</samlp:SessionIndex>
</samlp:LogoutRequest>

XML
            ],
            'With signature and without NameID encryption and with NameID format and with session index' => [true, false, HttpMessageInterface::NAMEID_PERSISTENT, 'baz', <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:NameID SPNameQualifier="http://sp.example.com/123" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
  <samlp:SessionIndex>baz</samlp:SessionIndex>
</samlp:LogoutRequest>

XML
            ],
            'With signature and without NameID encryption and without NameID format and with session index' => [true, false, null, 'qux', <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:NameID SPNameQualifier="http://sp.example.com/123">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
  <samlp:SessionIndex>qux</samlp:SessionIndex>
</samlp:LogoutRequest>

XML
            ],
            'Without signature and with NameID encryption and with NameID format and with session index' => [false, true, HttpMessageInterface::NAMEID_EMAIL_ADDRESS, 'plugh', <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:EncryptedID>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
      <dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
        <xenc:EncryptedKey>
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
          <xenc:CipherData>
            <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/dsig:KeyInfo/xenc:EncryptedKey/xenc:CipherData}}</xenc:CipherValue>
          </xenc:CipherData>
        </xenc:EncryptedKey>
      </dsig:KeyInfo>
      <xenc:CipherData>
        <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/xenc:CipherData}}</xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedData>
  </saml:EncryptedID>
  <samlp:SessionIndex>plugh</samlp:SessionIndex>
</samlp:LogoutRequest>

XML
            ],
            'Without signature and with NameID encryption and without NameID format and with session index' => [false, true, null, 'xyzzy', <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:EncryptedID>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
      <dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
        <xenc:EncryptedKey>
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
          <xenc:CipherData>
            <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/dsig:KeyInfo/xenc:EncryptedKey/xenc:CipherData}}</xenc:CipherValue>
          </xenc:CipherData>
        </xenc:EncryptedKey>
      </dsig:KeyInfo>
      <xenc:CipherData>
        <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/xenc:CipherData}}</xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedData>
  </saml:EncryptedID>
  <samlp:SessionIndex>xyzzy</samlp:SessionIndex>
</samlp:LogoutRequest>

XML
            ],
            'Without signature and without NameID encryption and with NameID format and with session index' => [false, false, HttpMessageInterface::NAMEID_KERBEROS, 'fred', <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:NameID SPNameQualifier="http://sp.example.com/123" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
  <samlp:SessionIndex>fred</samlp:SessionIndex>
</samlp:LogoutRequest>

XML
            ],
            'Without signature and without NameID encryption and without NameID format and with session index' => [false, false, null, 'bazz', <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:NameID SPNameQualifier="http://sp.example.com/123">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
  <samlp:SessionIndex>bazz</samlp:SessionIndex>
</samlp:LogoutRequest>

XML
            ],
            'With signature and with NameID encryption and with NameID format and without session index' => [true, true, HttpMessageInterface::NAMEID_TRANSIENT, null, <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:EncryptedID>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
      <dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
        <xenc:EncryptedKey>
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
          <xenc:CipherData>
            <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/dsig:KeyInfo/xenc:EncryptedKey/xenc:CipherData}}</xenc:CipherValue>
          </xenc:CipherData>
        </xenc:EncryptedKey>
      </dsig:KeyInfo>
      <xenc:CipherData>
        <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/xenc:CipherData}}</xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedData>
  </saml:EncryptedID>
</samlp:LogoutRequest>

XML
            ],
            'With signature and with NameID encryption and without NameID format and without session index' => [true, true, null, null, <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:EncryptedID>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
      <dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
        <xenc:EncryptedKey>
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
          <xenc:CipherData>
            <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/dsig:KeyInfo/xenc:EncryptedKey/xenc:CipherData}}</xenc:CipherValue>
          </xenc:CipherData>
        </xenc:EncryptedKey>
      </dsig:KeyInfo>
      <xenc:CipherData>
        <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/xenc:CipherData}}</xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedData>
  </saml:EncryptedID>
</samlp:LogoutRequest>

XML
            ],
            'With signature and without NameID encryption and with NameID format and without session index' => [true, false, HttpMessageInterface::NAMEID_ENTITY, null, <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:NameID SPNameQualifier="http://sp.example.com/123" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
</samlp:LogoutRequest>

XML
            ],
            'With signature and without NameID encryption and without NameID format and without session index' => [true, false, null, null, <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:NameID SPNameQualifier="http://sp.example.com/123">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
</samlp:LogoutRequest>

XML
            ],
            'Without signature and with NameID encryption and with NameID format and without session index' => [false, true, HttpMessageInterface::NAMEID_WINDOWS_DOMAIN_QUALIFIED_NAME, null, <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:EncryptedID>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
      <dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
        <xenc:EncryptedKey>
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
          <xenc:CipherData>
            <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/dsig:KeyInfo/xenc:EncryptedKey/xenc:CipherData}}</xenc:CipherValue>
          </xenc:CipherData>
        </xenc:EncryptedKey>
      </dsig:KeyInfo>
      <xenc:CipherData>
        <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/xenc:CipherData}}</xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedData>
  </saml:EncryptedID>
</samlp:LogoutRequest>

XML
            ],
            'Without signature and with NameID encryption and without NameID format and without session index' => [false, true, null, null, <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:EncryptedID>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
      <dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
        <xenc:EncryptedKey>
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
          <xenc:CipherData>
            <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/dsig:KeyInfo/xenc:EncryptedKey/xenc:CipherData}}</xenc:CipherValue>
          </xenc:CipherData>
        </xenc:EncryptedKey>
      </dsig:KeyInfo>
      <xenc:CipherData>
        <xenc:CipherValue>{{saml:EncryptedID/xenc:EncryptedData/xenc:CipherData}}</xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedData>
  </saml:EncryptedID>
</samlp:LogoutRequest>

XML
            ],
            'Without signature and without NameID encryption and with NameID format and without session index' => [false, false, HttpMessageInterface::NAMEID_X509_SUBJECT_NAME, null, <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:NameID SPNameQualifier="http://sp.example.com/123" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
</samlp:LogoutRequest>

XML
            ],
            'Without signature and without NameID encryption and without NameID format and without session index' => [false, false, null, null, <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/logout">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <saml:NameID SPNameQualifier="http://sp.example.com/123">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
</samlp:LogoutRequest>

XML
            ]
        ];
    }

    /**
     * @dataProvider isLogoutRequestSignatureRequired_isNameIdEncryptionRequired_nameIdFormat_sessionIndex_expected_Provider
     * @test
     * @param bool $isLogoutRequestSignatureRequired
     * @param bool $isNameIdEncryptionRequired
     * @param string|null $nameIdFormat
     * @param string|null $sessionIndex
     * @param string $expected
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     * @throws MalformedUriException
     * @throws SamlFlowServiceException
     * @throws SamlCannotGenerateSignatureException
     * @throws SamlCannotLoadCryptoKeyException
     * @throws MalformedPathQueryFragmentException
     * @throws SamlDocumentCannotWriteTextException
     */
    public function Can_generate_logout_uri(
        bool $isLogoutRequestSignatureRequired,
        bool $isNameIdEncryptionRequired,
        ?string $nameIdFormat,
        ?string $sessionIndex,
        string $expected
    ) : void {

        // session
        $dateTime = new DateTimeImmutable('2018-07-12T14:38:55.529Z');
        $returnUri = XUri::newFromString('https://app.example.com/xyzzy');
        $uuid = $this->newMock(UuidInterface::class);
        $uuid->expects(static::atLeastOnce())
            ->method('toString')
            ->willReturn('a9f2131e-1b01-4838-afc4-a98845dacf43');
        $uuidFactory = $this->newMock(UuidFactoryInterface::class);
        $uuidFactory->expects(static::atLeastOnce())
            ->method('uuid4')
            ->willReturn($uuid);
        $sessionIndexRegistry = $this->newMock(SessionIndexRegistryInterface::class);
        $sessionIndexRegistry->expects(static::atLeastOnce())
            ->method('getSessionIndex')
            ->with(static::equalTo('_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7'))
            ->willReturn($sessionIndex);

        // saml configuration
        $keys = static::newServiceProviderCryptoKeyPairFactory()
            ->newCryptoKeyPair();
        $saml = $this->newMock(SamlConfigurationInterface::class);
        $saml->expects(static::atLeastOnce())
            ->method('getServiceProviderEntityId')
            ->willReturn('http://sp.example.com/123');
        $saml->expects(static::atLeastOnce())
            ->method('getIdentityProviderSingleLogoutUri')
            ->willReturn(XUri::newFromString('https://idp.example.com/logout'));
        if($isLogoutRequestSignatureRequired) {
            $saml->expects(static::atLeastOnce())
                ->method('getServiceProviderPrivateKey')
                ->willReturn($keys->getPrivateKey());
            $saml->expects(static::atLeastOnce())
                ->method('getServiceProviderX509Certificate')
                ->willReturn($keys->getPublicKey());
        }
        $saml->expects(static::atLeastOnce())
            ->method('isLogoutRequestSignatureRequired')
            ->willReturn($isLogoutRequestSignatureRequired);
        $saml->expects(static::atLeastOnce())
            ->method('getServiceProviderNameIdFormat')
            ->willReturn($nameIdFormat);
        if($isNameIdEncryptionRequired) {
            $saml->expects( static::atLeastOnce())
                ->method('getIdentityProviderX509Certificate')
                ->willReturn(static::newIdentityProviderCryptoKeyPairFactory()
                    ->withDigestAlgorithm('sha1')
                    ->newCryptoKeyPair()
                    ->getPublicKey()
                );
        }
        $saml->expects(static::atLeastOnce())
            ->method('isNameIdEncryptionRequired')
            ->willReturn($isNameIdEncryptionRequired);

        // bootstrap service
        /** @var EventDispatcherInterface $eventDispatcher */
        /** @var ContextLoggerInterface $logger */
        /** @var UuidFactoryInterface $uuidFactory */
        /** @var SessionIndexRegistryInterface $sessionIndexRegistry */
        /** @var SamlConfigurationInterface $saml */
        $eventDispatcher = $this->newMock(EventDispatcherInterface::class);
        $logger = $this->newMock(ContextLoggerInterface::class);
        $service = new SamlFlowService(
            $saml,
            $dateTime,
            $logger,
            $uuidFactory,
            $eventDispatcher,
            static::newDocumentFactory(),
            $sessionIndexRegistry
        );

        // act
        $logoutUri = $service->getLogoutUri('_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7', $returnUri);

        // assert
        static::assertEquals('https://idp.example.com/logout', $logoutUri->toBaseUri()->atPath($logoutUri->getPath())->toString());
        if($isLogoutRequestSignatureRequired) {
            static::assertEquals(
                SamlHttpMessageUri::newFromString($logoutUri->toString())
                    ->withoutQueryParams([
                        HttpMessageInterface::PARAM_SAML_SIGALG,
                        HttpMessageInterface::PARAM_SAML_SIGNATURE
                    ])
                    ->withSignature($keys->getPrivateKey())
                    ->toString(),
                $logoutUri->toString()
            );
        }
        $logoutRequestDocument = self::newDocumentFactory()->newMessageDocument(
            gzinflate(base64_decode($logoutUri->getQueryParam(HttpMessageInterface::PARAM_SAML_REQUEST)))
        )->toFormattedDocument();
        $ciphers = new StringDictionary();
        $encryptedKeyCipherData = $logoutRequestDocument
            ->withNamespace('dsig', Document::NS_DS)
            ->query('saml:EncryptedID/xenc:EncryptedData/dsig:KeyInfo/xenc:EncryptedKey/xenc:CipherData');
        if($encryptedKeyCipherData->length > 0) {
            $ciphers->set('saml:EncryptedID/xenc:EncryptedData/dsig:KeyInfo/xenc:EncryptedKey/xenc:CipherData', trim($encryptedKeyCipherData->item(0)->textContent));
        }
        $encryptedDataCipherData = $logoutRequestDocument
            ->withNamespace('dsig', Document::NS_DS)
            ->query('saml:EncryptedID/xenc:EncryptedData/xenc:CipherData');
        if($encryptedKeyCipherData->length > 0) {
            $ciphers->set('saml:EncryptedID/xenc:EncryptedData/xenc:CipherData', trim($encryptedDataCipherData->item(0)->textContent));
        }
        $message = <<<XML
{$logoutRequestDocument->saveXML()}
XML;
        static::assertEquals((new StringEx($expected))->interpolate($ciphers)->toString(), $message);
    }
}
