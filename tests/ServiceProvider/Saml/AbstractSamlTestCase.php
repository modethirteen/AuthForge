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
namespace modethirteen\AuthForge\Tests\ServiceProvider\Saml;

use modethirteen\AuthForge\Common\Http\ServerRequestEx;
use modethirteen\AuthForge\ServiceProvider\Saml\DocumentFactory;
use modethirteen\AuthForge\ServiceProvider\Saml\DocumentFactoryInterface;
use modethirteen\AuthForge\ServiceProvider\Saml\DocumentSchemaResolverInterface;
use modethirteen\AuthForge\Tests\AbstractTestCase;
use modethirteen\Crypto\Exception\CryptoKeyFactoryCannotConstructCryptoKeyException;
use modethirteen\Crypto\ImportCryptoKeyPairFactory;
use modethirteen\Http\XUri;
use modethirteen\XArray\XArray;

abstract class AbstractSamlTestCase extends AbstractTestCase {

    const KEY_IDP_PRIVATE = <<<TEXT
-----BEGIN PRIVATE KEY-----
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
tjrZBae8ssmUS7y9j//J74MaIVa3XQ==
-----END PRIVATE KEY-----
TEXT;

    const KEY_IDP_X509 = <<<TEXT
-----BEGIN CERTIFICATE-----
MIIFYjCCA0oCCQCbWD6pJkNM8DANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJD
QTEMMAoGA1UECAwDZm9vMQwwCgYDVQQHDANiYXIxDDAKBgNVBAoMA2JhejEMMAoG
A1UECwwDcXV4MQwwCgYDVQQDDANpZHAxHjAcBgkqhkiG9w0BCQEWD2lkcEBleGFt
cGxlLmNvbTAeFw0yMTAxMTAwMTM5MTFaFw0yMTAyMDkwMTM5MTFaMHMxCzAJBgNV
BAYTAkNBMQwwCgYDVQQIDANmb28xDDAKBgNVBAcMA2JhcjEMMAoGA1UECgwDYmF6
MQwwCgYDVQQLDANxdXgxDDAKBgNVBAMMA2lkcDEeMBwGCSqGSIb3DQEJARYPaWRw
QGV4YW1wbGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAt/7X
c5FzcUXbStaEVyYyDIfNRmjXEo4O9dFlZUOgoerFir2igDafkWdUuejCn8aWkNFV
8wG5Aow8v3dDyWk2E54ndpZ5N9heRFTjMtG+P9sV0bVnFWMF2IUx13RqnlSIPb13
CG7rWkm2WztDRCD1PxWz4m9dx2Jr5kPRYeguVZpsmJZfTl5sgMznpkJz1m/6Aak3
YhbObn8tGdJkoFfgLobzCqJk519sHXhWs5slNHtryDTcakhGeEaFu9UldO+rd5Nr
7uhITYCemq4M8vhcw2o30kuxcQKYVXxXcnL+7Ay9z0Tx1knJvdnnNCOVJLAujqvN
NfdKvPR8LlimaucswjDwXukTN90uPplTky+LWG7DofrYUham/No+8S0nhEtPycqs
ou1gsLvI6oVUz8rT3NIm3tn0HBOGQ8c21mPbg3qMlI2D7J7BUMvz3gAMkdcoiGEr
6Gwh4x+7iyr8Yl1aGbn0oAq7rVoyTG4ee8TmwFoqeBJCk1x+vbN0RctFmSGlUmmR
WJdr3ezJynugp9KOpgUMGsKv4rNsRPX3+/maqzWaF27B5SJwHSmVGSkIg9sf9iix
ELUaPHuRa0dtgQj68uNvM9hPzgrhneJoQTjAwKXpPfHldijO2BK6mn9qK9uR7xKh
C4T7/b5mncLKk+q+vU+adFvs7Mr46CZEENqVxm0CAwEAATANBgkqhkiG9w0BAQsF
AAOCAgEAB3ZHMZABU9vcKGc3TRKyksNL7hXdQymJpHAzxub0a0FDfJMrU0eJ2Ged
fhBtBi8ohMvBanuQZRP4GVhPxQWmVpA/84MA/rIxhp7FX4d80u+yp6I/IVLZc1u5
BQRC8fJU/ynm00AqpXv0C0Hj1dGHcxWSmn0n3zmTA0NtkN7p0B+06E0vUJ0skv61
cJ8mmdC9T2+8lsxQHBMRZaklFfTMMTmoEqqCMn1XOGeAtPO5yZr6Bqozh+xty26m
AXrVIEeMfPfDQRrvY/Q448sJO647aYA8GraVUSue46FHBYHsyqVIWi+Fc4Xs9fdB
xzg1qlumz9+EmpK5WsrsXGYUWFFSqZfLOqS8Q7NdYee4QCkWr6QNsjIEhmvVvVEV
fxH6kLsEB0lYK830CNlFCCqfN5GG2Y2nwwvNieTMeInhoO2jMx/4DEYTi3aWs4bS
MKF3RjldA+xaUvyiXlbUWPrEC2fGZr7KUoU9gagrk5JM/HzDdZ9H9GOY5QyOFTSh
72E4HmVOUQ3HQivsxTHmB7irpDbbJpHzz6WbNIirHifSpEQ1O5hPVLnUHsnRegmO
NEb1mu1JZXF8bu8gw1uKCVGLQ6JxLZEQxqy7tyOKF9Z5XJUuZqngmgVqqtvDdEnM
17foWWvNsBhGj4ahc6JSn5KQKwPm/O1OoH6F5W+NL1uSF0Srnpw=
-----END CERTIFICATE-----
TEXT;

    const KEY_SP_PRIVATE = <<<TEXT
-----BEGIN PRIVATE KEY-----
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
jGIxA/0KGa12yIyOPQdnxCL579ILhw==
-----END PRIVATE KEY-----
TEXT;

    const KEY_SP_X509 = <<<TEXT
-----BEGIN CERTIFICATE-----
MIIFXjCCA0YCCQDU3pFpc4uvLzANBgkqhkiG9w0BAQsFADBxMQswCQYDVQQGEwJV
UzEMMAoGA1UECAwDZm9vMQwwCgYDVQQHDANiYXIxDDAKBgNVBAoMA2JhejEMMAoG
A1UECwwDcXV4MQswCQYDVQQDDAJzcDEdMBsGCSqGSIb3DQEJARYOc3BAZXhhbXBs
ZS5jb20wHhcNMjEwMTEwMDEzOTM5WhcNMjEwMjA5MDEzOTM5WjBxMQswCQYDVQQG
EwJVUzEMMAoGA1UECAwDZm9vMQwwCgYDVQQHDANiYXIxDDAKBgNVBAoMA2JhejEM
MAoGA1UECwwDcXV4MQswCQYDVQQDDAJzcDEdMBsGCSqGSIb3DQEJARYOc3BAZXhh
bXBsZS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDhU04deKfa
DkflHpYvZirtOub8uddWK9FAAVSgJhbZtZ50MfKnuc0V8vGrGST2UavRRS2tpk3c
KTWW4EVTxodIg8cEX0x31LQq8lhaBl5g69I2JY6k7fqB69JBwlXRzO93uFrRi+cx
ntKyrmzn+HiKvI6/l+TO2L+itlrJPl15c4MxXb5Uvnp7YBOEDnFZpfj7JnYGgQh6
ck/tttslxzg4qpA7c+y09tu16CCuWk88NHIuUiNR8YknzN1oXutKW4W1kBqfVqf5
RS7/d7PvGSic+HREo8uWlWlLbQZnoSAHlcjTV5NzEUjdtRr/SUbY/stEGbHgoNzX
dZC/1FZHn8xCE5UsqYybpqaH8MrczRVc+ploiP/bma8ysyDblVGz/x3TKfDy4vJC
BmzzSshle4HfiNF+58RqUzibOnJOKLv0fS8EPMkqWBR3U0cvdoV7OTwX9DH0JCtV
YpdGwYTciWg79ozdbZwVq0UVx1w0i+1ZfDOnPkcb4vy2dra23t3xzyj6itaOtQSL
DZ2htOj4qn35mBO9LFD1WkJyF4EbdY+kPzWSsoPJ2Up1srl9GDB6JzFxbpm/DSNS
U93ZXPg3NWuhGrDR0MJDchBPTQo6SvTiNYwz/qiGuYUwWYEDW2EedwsQ+F+/54cQ
SnnlCCYfr+VMeewCQoVIJaWeT7GHyJu43QIDAQABMA0GCSqGSIb3DQEBCwUAA4IC
AQBdEOMzhKhH0RGl6bOrpn53wYzXTcw3evJvQLSz5dBqT92/XmlzD9eeP9IflbOt
L8AQcjRYCwhMlDqmei1/0IZ4KUemvtAU8uLs3G3KI9YXB5ooiJ4wuChgi88ng1of
XNNa6/Sg1zi9uIYxReHo26xED3+Le3ICEXnFsDoO/czMIxMtn1fBEZCua2aXiQKE
hBMQKeo2EihIedCc1N8zPYlt5NLJ3Y5glrMryOCsl6bUIp40JvPuqL2XfJJ6RVDq
pnSq3+2zv/6fTOmiZufj91/LcRO4pU+Fgacjyh9y+NR6JRL9WuTh0Znc2c13PAfg
FmGeh+L6llY5SvRRarVfeuxTJ7ZrQhLu4LR+Hkmnn0JqdNNUzBSz7pfnnqbxpmSu
rtKtvnWZ6xOWbBZzXsm+LV1QibkE66nbaMesmRSG72rk2UzmBht4j9CjbgYfAKSg
cXPVQLvDAET7cEzKMnnKSVWYgDQsw92eyaKSpL0IJy8JH77xqhFKokadHEOWGY3m
k5KK/AP1o4r5LJx/Tee6CRErz6DJEy3+QyCx26Y9mqJ4B1d36pz+/q4P21lxjLEe
IV8AHtQDSDrpDwIAgPW4Ot3j70YK9DP+5TeLQKRhtMpPlE8ApU+U5d24BAhyDgUt
6KxYNoaDbzySXzmaHYMih38767rL8D1HbiEzukbf7+FYZQ==
-----END CERTIFICATE-----
TEXT;

    // original unsigned samlp:AuthnRequest message is located at https://www.samltool.com/generic_sso_req.php
    const MESSAGE_UNSIGNED_AUTHN_REQUEST = <<<XML
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24" Version="2.0" ProviderName="SP test" IssueInstant="2014-07-16T23:52:45Z" Destination="http://idp.example.com/SSOService.php" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="http://sp.example.com/demo1/index.php?acs">
  <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
XML;

    // original unsigned samlp:LogoutRequest message is located at https://www.samltool.com/generic_slo_req.php
    const MESSAGE_UNSIGNED_LOGOUT_REQUEST = <<<XML
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d" Version="2.0" IssueInstant="2014-07-18T01:13:06Z" Destination="http://idp.example.com/SingleLogoutService.php">
  <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>
  <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7</saml:NameID>
</samlp:LogoutRequest>
XML;

    // original unsigned samlp:LogoutResponse message is located at https://www.samltool.com/generic_slo_res.php
    const MESSAGE_UNSIGNED_LOGOUT_RESPONSE = <<<XML
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_6c3737282f007720e736f0f4028feed8cb9b40291c" Version="2.0" IssueInstant="2014-07-18T01:13:06Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:LogoutResponse>
XML;

    /**
     * @note (modethirteen, 20210111): saml:Assertion requires xmlns:saml and xmlns:samlp namespace definitions on entity before encryption
     * @see https://www.samltool.com/generic_sso_res.php
     */
    const MESSAGE_UNSIGNED_RESPONSE_WITH_UNSIGNED_UNENCRYPTED_ASSERTION = <<<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
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
XML;

    /**
     * @param string $message
     * @return string
     */
    protected static function getPostEncodedHttpMessage(string $message) : string {
        return base64_encode($message);
    }

    /**
     * @param string $message
     * @return string
     */
    protected static function getRedirectEncodedDeflatedHttpMessage(string $message) : string {
        return base64_encode(gzdeflate($message));
    }

    protected static function newDocumentFactory() : DocumentFactoryInterface {
        $directory = implode(DIRECTORY_SEPARATOR, [
            rtrim(self::getProjectRootDirectory(), DIRECTORY_SEPARATOR), 'redist', 'OneLogin', 'schemas'
        ]);
        return new DocumentFactory(new class($directory) implements DocumentSchemaResolverInterface {

            /**
             * @var string
             */
            private $directory;

            /**
             * @param string $directory - schema collection root directory
             */
            public function __construct(string $directory) {
                $this->directory = $directory;
            }

            public function resolve(string $schema): string {
                return $this->directory . DIRECTORY_SEPARATOR . "{$schema}.xsd";
            }
        });
    }

    /**
     * @return ImportCryptoKeyPairFactory
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     */
    protected static function newIdentityProviderCryptoKeyPairFactory() : ImportCryptoKeyPairFactory {
        if(
            openssl_x509_check_private_key(
                openssl_x509_read(static::KEY_IDP_X509),
                openssl_pkey_get_private(static::KEY_IDP_PRIVATE)
            )
        ) {
            return new ImportCryptoKeyPairFactory(static::KEY_IDP_PRIVATE, static::KEY_IDP_X509);
        } else {
            throw new CryptoKeyFactoryCannotConstructCryptoKeyException('mismatched private key and x.509 certificate');
        }
    }

    /**
     * @return ImportCryptoKeyPairFactory
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     */
    protected static function newServiceProviderCryptoKeyPairFactory() : ImportCryptoKeyPairFactory {
        if(
            openssl_x509_check_private_key(
                openssl_x509_read(static::KEY_SP_X509),
                openssl_pkey_get_private(static::KEY_SP_PRIVATE)
            )
        ) {
            return new ImportCryptoKeyPairFactory(static::KEY_SP_PRIVATE, static::KEY_SP_X509);
        } else {
            throw new CryptoKeyFactoryCannotConstructCryptoKeyException('mismatched private key and x.509 certificate');
        }
    }

    /**
     * @param XUri $uri
     * @return ServerRequestEx
     */
    protected function newHttpGetRequest(XUri $uri) : ServerRequestEx {
        $request = $this->newMock(ServerRequestEx::class);
        $request->expects(static::any())
            ->method('getBody')
            ->willReturn(new XArray([]));
        $request->expects(static::any())
            ->method('getParam')
            ->willReturnCallback(function(string $param) use ($uri) {
                return $uri->getQueryParam($param);
            });
        $request->expects(static::any())
            ->method('getUri')
            ->willReturn($uri);
        $request->expects(static::any())
            ->method('getQueryParams')
            ->willReturn($uri->getQueryParams());
        $request->expects(static::any())
            ->method('isPost')
            ->willReturn(false);

        /** @var ServerRequestEx $request */
        return $request;
    }

    /**
     * @param XUri $uri
     * @param XArray $body
     * @return ServerRequestEx
     */
    protected function newHttpPostRequest(XUri $uri, XArray $body) : ServerRequestEx {
        $request = $this->newMock(ServerRequestEx::class);
        $request->expects(static::any())
            ->method('getBody')
            ->willReturn($body);
        $request->expects(static::any())
            ->method('getParam')
            ->willReturnCallback(function(string $param) use ($uri, $body) {
                $value = $body->getVal($param);
                if($value !== null) {
                    return $value;
                }
                return $uri->getQueryParam($param);
            });
        $request->expects(static::any())
            ->method('getUri')
            ->willReturn($uri);
        $request->expects(static::any())
            ->method('getQueryParams')
            ->willReturn($uri->getQueryParams());
        $request->expects(static::any())
            ->method('isPost')
            ->willReturn(true);

        /** @var ServerRequestEx $request  */
        return $request;
    }
}
