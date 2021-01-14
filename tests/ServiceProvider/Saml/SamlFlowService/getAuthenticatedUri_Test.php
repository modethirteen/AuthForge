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
use modethirteen\AuthForge\Common\Exception\AuthServiceException;
use modethirteen\AuthForge\Common\Exception\NotSupportedException;
use modethirteen\AuthForge\Common\Logger\ContextLoggerInterface;
use modethirteen\AuthForge\ServiceProvider\Saml\Event\SamlAuthnResponseFlowEvent;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotGenerateSignatureException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlFlowServiceException;
use modethirteen\AuthForge\ServiceProvider\Saml\Http\HttpMessageInterface;
use modethirteen\AuthForge\ServiceProvider\Saml\Http\SamlHttpMessageUri;
use modethirteen\AuthForge\ServiceProvider\Saml\SamlConfigurationInterface;
use modethirteen\AuthForge\ServiceProvider\Saml\SamlFlowService;
use modethirteen\AuthForge\ServiceProvider\Saml\SessionIndexRegistryInterface;
use modethirteen\AuthForge\Tests\ServiceProvider\Saml\AbstractSamlTestCase;
use modethirteen\Crypto\Exception\CryptoKeyCannotParseCryptoKeyTextException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryCannotConstructCryptoKeyException;
use modethirteen\Http\Exception\MalformedUriException;
use modethirteen\Http\Mock\MockPlug;
use modethirteen\XArray\XArray;
use Psr\EventDispatcher\EventDispatcherInterface;
use Ramsey\Uuid\UuidFactoryInterface;

class getAuthenticatedUri_Test extends AbstractSamlTestCase {
    const CASE_FULFILLED_REQUIRED = 1;
    const CASE_FULFILLED_NOT_REQUIRED = 2;
    const CASE_UNFULFILLED_REQUIRED = 4;
    const CASE_UNFULFILLED_NOT_REQUIRED = 8;

    /**
     * Signed with AbstractSamlTestCase::KEY_IDP_PRIVATE (SHA1)
     * Encrypted with AbstractSamlTestCase::KEY_SP_X509 (AES128)
     * @see AbstractSamlTestCase::MESSAGE_UNSIGNED_RESPONSE_WITH_UNSIGNED_UNENCRYPTED_ASSERTION
     */
    const MESSAGE_SIGNED_RESPONSE_WITH_SIGNED_ENCRYPTED_ASSERTION = <<<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfx6ee48728-2c67-22bb-5f7d-fbdfd28b00e4" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx6ee48728-2c67-22bb-5f7d-fbdfd28b00e4"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>XlAwCskuA4mbcUmHtMlhTWvatn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>EY1O1LpF3XjHDMq1K4mBxiRKQxEXyyXWzb98Hr4eCHS3+mVVxhtcM0DJaHrwwuSD18dOt25tCrxRY7v6zJd9tldGbpPhgBh4ExMaCjiKJFfXOXHx2jrSflRgVFANk459Pf8kNrWjLzdXAMXXm9SWB+gIGx7Rx9XMxTUaYYhOULuNdnlOLKu2nGOlPZSMfIhjP76fjpnlC+fBv4mPPCn507AA7JRsBfJsRGiPZBBx2qy1g5l5UuPjjLLvwy4hBaYwn+EY7s7fo5u7tgdXdf8Tq80A9POH6ma3l/HKeObKWzAJgoMX1eGkYRI0P3xrm5hDJajLCuUUZscD1/REQGPJWEB9XT1jVZ8XrNvpoTRwc+Aa4VDr+abRdjxBr6mycl5KUZFhe/rRIUHo23MeYX7KCAjoSkW6wClTnhkqkxoJ+yFPI/9AQ16Jwi3XSJYbzHA460CVPSqfvtwR8tX4A+TTkVVI6z/wg5A6wgdQ5h3fcWP7ZJ0IKcnAwNtcn3upItVF6J1uUw+slYELzydg78ICluA01O3biuX7IExMseBFmeFL5gDaoXeJsgKGeC0eAYk/Q0ib2N3A0WVJ+nuBtXEErDhcIpi40yB9USdZdS+lJjYFlY/fWXVoooQ/iN4K9cVrwDggeNxRN8C1eY0R5H6DL3TW5AvRK982aAaO18XEcRY=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIFYjCCA0oCCQCbWD6pJkNM8DANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJDQTEMMAoGA1UECAwDZm9vMQwwCgYDVQQHDANiYXIxDDAKBgNVBAoMA2JhejEMMAoGA1UECwwDcXV4MQwwCgYDVQQDDANpZHAxHjAcBgkqhkiG9w0BCQEWD2lkcEBleGFtcGxlLmNvbTAeFw0yMTAxMTAwMTM5MTFaFw0yMTAyMDkwMTM5MTFaMHMxCzAJBgNVBAYTAkNBMQwwCgYDVQQIDANmb28xDDAKBgNVBAcMA2JhcjEMMAoGA1UECgwDYmF6MQwwCgYDVQQLDANxdXgxDDAKBgNVBAMMA2lkcDEeMBwGCSqGSIb3DQEJARYPaWRwQGV4YW1wbGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAt/7Xc5FzcUXbStaEVyYyDIfNRmjXEo4O9dFlZUOgoerFir2igDafkWdUuejCn8aWkNFV8wG5Aow8v3dDyWk2E54ndpZ5N9heRFTjMtG+P9sV0bVnFWMF2IUx13RqnlSIPb13CG7rWkm2WztDRCD1PxWz4m9dx2Jr5kPRYeguVZpsmJZfTl5sgMznpkJz1m/6Aak3YhbObn8tGdJkoFfgLobzCqJk519sHXhWs5slNHtryDTcakhGeEaFu9UldO+rd5Nr7uhITYCemq4M8vhcw2o30kuxcQKYVXxXcnL+7Ay9z0Tx1knJvdnnNCOVJLAujqvNNfdKvPR8LlimaucswjDwXukTN90uPplTky+LWG7DofrYUham/No+8S0nhEtPycqsou1gsLvI6oVUz8rT3NIm3tn0HBOGQ8c21mPbg3qMlI2D7J7BUMvz3gAMkdcoiGEr6Gwh4x+7iyr8Yl1aGbn0oAq7rVoyTG4ee8TmwFoqeBJCk1x+vbN0RctFmSGlUmmRWJdr3ezJynugp9KOpgUMGsKv4rNsRPX3+/maqzWaF27B5SJwHSmVGSkIg9sf9iixELUaPHuRa0dtgQj68uNvM9hPzgrhneJoQTjAwKXpPfHldijO2BK6mn9qK9uR7xKhC4T7/b5mncLKk+q+vU+adFvs7Mr46CZEENqVxm0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAB3ZHMZABU9vcKGc3TRKyksNL7hXdQymJpHAzxub0a0FDfJMrU0eJ2GedfhBtBi8ohMvBanuQZRP4GVhPxQWmVpA/84MA/rIxhp7FX4d80u+yp6I/IVLZc1u5BQRC8fJU/ynm00AqpXv0C0Hj1dGHcxWSmn0n3zmTA0NtkN7p0B+06E0vUJ0skv61cJ8mmdC9T2+8lsxQHBMRZaklFfTMMTmoEqqCMn1XOGeAtPO5yZr6Bqozh+xty26mAXrVIEeMfPfDQRrvY/Q448sJO647aYA8GraVUSue46FHBYHsyqVIWi+Fc4Xs9fdBxzg1qlumz9+EmpK5WsrsXGYUWFFSqZfLOqS8Q7NdYee4QCkWr6QNsjIEhmvVvVEVfxH6kLsEB0lYK830CNlFCCqfN5GG2Y2nwwvNieTMeInhoO2jMx/4DEYTi3aWs4bSMKF3RjldA+xaUvyiXlbUWPrEC2fGZr7KUoU9gagrk5JM/HzDdZ9H9GOY5QyOFTSh72E4HmVOUQ3HQivsxTHmB7irpDbbJpHzz6WbNIirHifSpEQ1O5hPVLnUHsnRegmONEb1mu1JZXF8bu8gw1uKCVGLQ6JxLZEQxqy7tyOKF9Z5XJUuZqngmgVqqtvDdEnM17foWWvNsBhGj4ahc6JSn5KQKwPm/O1OoH6F5W+NL1uSF0Srnpw=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  
<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><xenc:CipherData><xenc:CipherValue>QqhYfTFjxHRgRCQU5y43m53ia0BNF9qkO0Qi4y8xdmyowzA5k4LkNU5lRy8ZTbQFJHTPIxWzXwLIZcnZCcX+rlaUz90MMrNNVyCTViDu8ETAMoHyyBxU9Zk6AndyYWfk6yWUN83JFCgbfiFv5gi5IYdB+xxuKnQX1m3TNhJQbRfccHGRSulgibA1cpc93PF4DBM4wKvCvs0A9Uh3XY+Ep49XrO/pucporW6+yY8iDWtT7TPqwvrCTQuouSETy2y1F3BEzSYMUK5zv+MdybWlYn0TbOq7DxLCwGF8+62DnBOINEbxmNXUpAfXPTd6Yxzh+2IJYkpCyfqP+raHg9oIYxnLVz0m/vlJealgL+fafa3jVCCMPyd6rfLOPmz4KI5ukseR2ApRcK33u84naxmdiCH93mwYkaZ+k3AuaYaEkUxieBW+z/LVCZuvku61wf5TvQrmhvi1yuRA4sy5+d2cTQTwxI5BuevD4h/dzm70YatsVH1jr8QLOlErZ9oy3K0258W8HOjS7RY06EVst7NscfnjuFTD9Suhu8TJ7ySFf0wCUpz2qvScO4CfnoAyqX7e3WffxJZHS6YPY73TFSxNz177jv8v5jqOhAZbGum7+u1fgtcJnvgeMG+pPtCFyBqwVMPvHYAojOIi1b2pxMvcSkpCojROWoJV9pp7qIa8AI0=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></dsig:KeyInfo>
   <xenc:CipherData>
      <xenc:CipherValue>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</xenc:CipherValue>
   </xenc:CipherData>
</xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>
XML;

    /**
     * Signed with AbstractSamlTestCase::KEY_IDP_PRIVATE (SHA1)
     * @see AbstractSamlTestCase::MESSAGE_UNSIGNED_RESPONSE_WITH_UNSIGNED_UNENCRYPTED_ASSERTION
     */
    const MESSAGE_SIGNED_RESPONSE_WITH_SIGNED_UNENCRYPTED_ASSERTION = <<<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfx6ee48728-2c67-22bb-5f7d-fbdfd28b00e4" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx6ee48728-2c67-22bb-5f7d-fbdfd28b00e4"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>XlAwCskuA4mbcUmHtMlhTWvatn4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>EY1O1LpF3XjHDMq1K4mBxiRKQxEXyyXWzb98Hr4eCHS3+mVVxhtcM0DJaHrwwuSD18dOt25tCrxRY7v6zJd9tldGbpPhgBh4ExMaCjiKJFfXOXHx2jrSflRgVFANk459Pf8kNrWjLzdXAMXXm9SWB+gIGx7Rx9XMxTUaYYhOULuNdnlOLKu2nGOlPZSMfIhjP76fjpnlC+fBv4mPPCn507AA7JRsBfJsRGiPZBBx2qy1g5l5UuPjjLLvwy4hBaYwn+EY7s7fo5u7tgdXdf8Tq80A9POH6ma3l/HKeObKWzAJgoMX1eGkYRI0P3xrm5hDJajLCuUUZscD1/REQGPJWEB9XT1jVZ8XrNvpoTRwc+Aa4VDr+abRdjxBr6mycl5KUZFhe/rRIUHo23MeYX7KCAjoSkW6wClTnhkqkxoJ+yFPI/9AQ16Jwi3XSJYbzHA460CVPSqfvtwR8tX4A+TTkVVI6z/wg5A6wgdQ5h3fcWP7ZJ0IKcnAwNtcn3upItVF6J1uUw+slYELzydg78ICluA01O3biuX7IExMseBFmeFL5gDaoXeJsgKGeC0eAYk/Q0ib2N3A0WVJ+nuBtXEErDhcIpi40yB9USdZdS+lJjYFlY/fWXVoooQ/iN4K9cVrwDggeNxRN8C1eY0R5H6DL3TW5AvRK982aAaO18XEcRY=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIFYjCCA0oCCQCbWD6pJkNM8DANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJDQTEMMAoGA1UECAwDZm9vMQwwCgYDVQQHDANiYXIxDDAKBgNVBAoMA2JhejEMMAoGA1UECwwDcXV4MQwwCgYDVQQDDANpZHAxHjAcBgkqhkiG9w0BCQEWD2lkcEBleGFtcGxlLmNvbTAeFw0yMTAxMTAwMTM5MTFaFw0yMTAyMDkwMTM5MTFaMHMxCzAJBgNVBAYTAkNBMQwwCgYDVQQIDANmb28xDDAKBgNVBAcMA2JhcjEMMAoGA1UECgwDYmF6MQwwCgYDVQQLDANxdXgxDDAKBgNVBAMMA2lkcDEeMBwGCSqGSIb3DQEJARYPaWRwQGV4YW1wbGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAt/7Xc5FzcUXbStaEVyYyDIfNRmjXEo4O9dFlZUOgoerFir2igDafkWdUuejCn8aWkNFV8wG5Aow8v3dDyWk2E54ndpZ5N9heRFTjMtG+P9sV0bVnFWMF2IUx13RqnlSIPb13CG7rWkm2WztDRCD1PxWz4m9dx2Jr5kPRYeguVZpsmJZfTl5sgMznpkJz1m/6Aak3YhbObn8tGdJkoFfgLobzCqJk519sHXhWs5slNHtryDTcakhGeEaFu9UldO+rd5Nr7uhITYCemq4M8vhcw2o30kuxcQKYVXxXcnL+7Ay9z0Tx1knJvdnnNCOVJLAujqvNNfdKvPR8LlimaucswjDwXukTN90uPplTky+LWG7DofrYUham/No+8S0nhEtPycqsou1gsLvI6oVUz8rT3NIm3tn0HBOGQ8c21mPbg3qMlI2D7J7BUMvz3gAMkdcoiGEr6Gwh4x+7iyr8Yl1aGbn0oAq7rVoyTG4ee8TmwFoqeBJCk1x+vbN0RctFmSGlUmmRWJdr3ezJynugp9KOpgUMGsKv4rNsRPX3+/maqzWaF27B5SJwHSmVGSkIg9sf9iixELUaPHuRa0dtgQj68uNvM9hPzgrhneJoQTjAwKXpPfHldijO2BK6mn9qK9uR7xKhC4T7/b5mncLKk+q+vU+adFvs7Mr46CZEENqVxm0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAB3ZHMZABU9vcKGc3TRKyksNL7hXdQymJpHAzxub0a0FDfJMrU0eJ2GedfhBtBi8ohMvBanuQZRP4GVhPxQWmVpA/84MA/rIxhp7FX4d80u+yp6I/IVLZc1u5BQRC8fJU/ynm00AqpXv0C0Hj1dGHcxWSmn0n3zmTA0NtkN7p0B+06E0vUJ0skv61cJ8mmdC9T2+8lsxQHBMRZaklFfTMMTmoEqqCMn1XOGeAtPO5yZr6Bqozh+xty26mAXrVIEeMfPfDQRrvY/Q448sJO647aYA8GraVUSue46FHBYHsyqVIWi+Fc4Xs9fdBxzg1qlumz9+EmpK5WsrsXGYUWFFSqZfLOqS8Q7NdYee4QCkWr6QNsjIEhmvVvVEVfxH6kLsEB0lYK830CNlFCCqfN5GG2Y2nwwvNieTMeInhoO2jMx/4DEYTi3aWs4bSMKF3RjldA+xaUvyiXlbUWPrEC2fGZr7KUoU9gagrk5JM/HzDdZ9H9GOY5QyOFTSh72E4HmVOUQ3HQivsxTHmB7irpDbbJpHzz6WbNIirHifSpEQ1O5hPVLnUHsnRegmONEb1mu1JZXF8bu8gw1uKCVGLQ6JxLZEQxqy7tyOKF9Z5XJUuZqngmgVqqtvDdEnM17foWWvNsBhGj4ahc6JSn5KQKwPm/O1OoH6F5W+NL1uSF0Srnpw=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="pfx82d0f248-aa5e-2d8c-af00-eee9f88d2526" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx82d0f248-aa5e-2d8c-af00-eee9f88d2526"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>H7XIyLoJAv+C0Sr7tqQQ9Lrplpg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>ahGS6W2Z1ZEriFF4jrH45h3dRV2J9uZi2jsiXC5NdjI5kVt05d6++BLsyJp0ZV+yQSgat1uj4pR7ziDNEc7qOq0vBkVV66w70nT3d/nmr3Q7zzu0LXW0C8Q0eIPg/aDQVyKVMGmkrqiVIpqVzdazlBUh3WPGUDorWuxph011eOig55M1YMAg8QHVh7QsNQepS0hXz6gTVA57EpD/ffSsoQATZy9Kf4INmAmcUXs9Dhzd9JcC2YBzpr9MhGfuIOfyK9LPQpZgM8cLLaMXV64c/8VQNTS/HmCPqBWNQErcv5bxBBw6Pyj7zDxVga35qXPC5CsLO7RwnpX60XXP4+wXiQTWvT1OWtEzU8NWJUepFK7vYyZZZdQhchyVE6VgUwBm0sDyJrgtO9HjVE1nYT04y7jOvoKauo5tq/MQR0PlU4IeaBZGjvjeHWKZxnCgbQmQG8b8fvjVAoeEgTlrCNbTDd3lqNWR6TQU4B+70iKysE4JYQ+dtndMJn6FOBRVy/hzXUpi9h0AYHpq5PDt4kuDWYiIq5Nfk7K0JxHyckS7q0PnaQURsA7Uz6ajAt9k7DH9fK9U/QxwZ2ga0ZNtBBfhDtGQ6fBdfcFkEJFSg4pWJXmae2ymLINmVRNnsWzAEZklai9rHL6NI9bZc2va9tM/2YHSD40Bei4aMYyEf/c3PLo=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIFYjCCA0oCCQCbWD6pJkNM8DANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJDQTEMMAoGA1UECAwDZm9vMQwwCgYDVQQHDANiYXIxDDAKBgNVBAoMA2JhejEMMAoGA1UECwwDcXV4MQwwCgYDVQQDDANpZHAxHjAcBgkqhkiG9w0BCQEWD2lkcEBleGFtcGxlLmNvbTAeFw0yMTAxMTAwMTM5MTFaFw0yMTAyMDkwMTM5MTFaMHMxCzAJBgNVBAYTAkNBMQwwCgYDVQQIDANmb28xDDAKBgNVBAcMA2JhcjEMMAoGA1UECgwDYmF6MQwwCgYDVQQLDANxdXgxDDAKBgNVBAMMA2lkcDEeMBwGCSqGSIb3DQEJARYPaWRwQGV4YW1wbGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAt/7Xc5FzcUXbStaEVyYyDIfNRmjXEo4O9dFlZUOgoerFir2igDafkWdUuejCn8aWkNFV8wG5Aow8v3dDyWk2E54ndpZ5N9heRFTjMtG+P9sV0bVnFWMF2IUx13RqnlSIPb13CG7rWkm2WztDRCD1PxWz4m9dx2Jr5kPRYeguVZpsmJZfTl5sgMznpkJz1m/6Aak3YhbObn8tGdJkoFfgLobzCqJk519sHXhWs5slNHtryDTcakhGeEaFu9UldO+rd5Nr7uhITYCemq4M8vhcw2o30kuxcQKYVXxXcnL+7Ay9z0Tx1knJvdnnNCOVJLAujqvNNfdKvPR8LlimaucswjDwXukTN90uPplTky+LWG7DofrYUham/No+8S0nhEtPycqsou1gsLvI6oVUz8rT3NIm3tn0HBOGQ8c21mPbg3qMlI2D7J7BUMvz3gAMkdcoiGEr6Gwh4x+7iyr8Yl1aGbn0oAq7rVoyTG4ee8TmwFoqeBJCk1x+vbN0RctFmSGlUmmRWJdr3ezJynugp9KOpgUMGsKv4rNsRPX3+/maqzWaF27B5SJwHSmVGSkIg9sf9iixELUaPHuRa0dtgQj68uNvM9hPzgrhneJoQTjAwKXpPfHldijO2BK6mn9qK9uR7xKhC4T7/b5mncLKk+q+vU+adFvs7Mr46CZEENqVxm0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAB3ZHMZABU9vcKGc3TRKyksNL7hXdQymJpHAzxub0a0FDfJMrU0eJ2GedfhBtBi8ohMvBanuQZRP4GVhPxQWmVpA/84MA/rIxhp7FX4d80u+yp6I/IVLZc1u5BQRC8fJU/ynm00AqpXv0C0Hj1dGHcxWSmn0n3zmTA0NtkN7p0B+06E0vUJ0skv61cJ8mmdC9T2+8lsxQHBMRZaklFfTMMTmoEqqCMn1XOGeAtPO5yZr6Bqozh+xty26mAXrVIEeMfPfDQRrvY/Q448sJO647aYA8GraVUSue46FHBYHsyqVIWi+Fc4Xs9fdBxzg1qlumz9+EmpK5WsrsXGYUWFFSqZfLOqS8Q7NdYee4QCkWr6QNsjIEhmvVvVEVfxH6kLsEB0lYK830CNlFCCqfN5GG2Y2nwwvNieTMeInhoO2jMx/4DEYTi3aWs4bSMKF3RjldA+xaUvyiXlbUWPrEC2fGZr7KUoU9gagrk5JM/HzDdZ9H9GOY5QyOFTSh72E4HmVOUQ3HQivsxTHmB7irpDbbJpHzz6WbNIirHifSpEQ1O5hPVLnUHsnRegmONEb1mu1JZXF8bu8gw1uKCVGLQ6JxLZEQxqy7tyOKF9Z5XJUuZqngmgVqqtvDdEnM17foWWvNsBhGj4ahc6JSn5KQKwPm/O1OoH6F5W+NL1uSF0Srnpw=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
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
     * Signed with AbstractSamlTestCase::KEY_IDP_PRIVATE (SHA1)
     * Encrypted with AbstractSamlTestCase::KEY_SP_X509 (AES128)
     * @see AbstractSamlTestCase::MESSAGE_UNSIGNED_RESPONSE_WITH_UNSIGNED_UNENCRYPTED_ASSERTION
     */
    const MESSAGE_SIGNED_RESPONSE_WITH_UNSIGNED_ENCRYPTED_ASSERTION = <<<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfx656e444c-c75e-edc7-45c2-01878435eb0a" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx656e444c-c75e-edc7-45c2-01878435eb0a"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>lmZsjWh+9GgEL4h/pCrHhlfhALQ=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>jB8s1stlI644nRejIDh26Qe+APNe1eznDVD17VD6iV7Vj3pJv/CxKJsI6iAXlN6uun6Us8QsUtayBAigeUT/p7Wgit0sQxo7XBtaJB74b4dT9cYsJNIyuLnhfFcUFBX11/Gx/hWtaOtSHadB9oXYz4ZA0Gma5iEPqWVub3TmD6I4lnrQnyaUIhVH0shGIkxGXTzowhVZRQ+0gL7Ip0lAgcX90Hg20GokxdrF9obwCKjXiY+enCG1F/11occddp8lN9r4l5LyqWWGIBQTHNRjh9YoQgCECqc6HW3ce5NTrn1/e5UjkzyCdqJ3fzFUzZPWoK4UlwpwK0y/jwKqyW3fSwOx2yRcpe9XWXHC82KcjGSEagaPRLNAs2uVJ0p1Oovrh4Aj+J6xnDCwwsekwC6gZzm7y5t9qCulcHEA+razWpmJhz4uimTeEeXAvZrOqC8uPzEZ77PETS90FIaj4Iq+m6x1Zfondzp3mO3Ujyw4atIsgjxgZNYr1EyW+t3EuHUdxMXnUhYXEreMtq+H77Ef/WLmHD4mwVGRwEgFrubhS8mXOf/au7VWtVbqgCb60vnF9PGy/I9clvwu9/c+bxIg5OE/fTHs+km1UFhqn1r4qntrttndC9XMxAzShYYrAtjP0MxFYm+/CNRwSwheIU5mpJMy3zaz1TAb4HrXj8QMc9U=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIFYjCCA0oCCQCbWD6pJkNM8DANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJDQTEMMAoGA1UECAwDZm9vMQwwCgYDVQQHDANiYXIxDDAKBgNVBAoMA2JhejEMMAoGA1UECwwDcXV4MQwwCgYDVQQDDANpZHAxHjAcBgkqhkiG9w0BCQEWD2lkcEBleGFtcGxlLmNvbTAeFw0yMTAxMTAwMTM5MTFaFw0yMTAyMDkwMTM5MTFaMHMxCzAJBgNVBAYTAkNBMQwwCgYDVQQIDANmb28xDDAKBgNVBAcMA2JhcjEMMAoGA1UECgwDYmF6MQwwCgYDVQQLDANxdXgxDDAKBgNVBAMMA2lkcDEeMBwGCSqGSIb3DQEJARYPaWRwQGV4YW1wbGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAt/7Xc5FzcUXbStaEVyYyDIfNRmjXEo4O9dFlZUOgoerFir2igDafkWdUuejCn8aWkNFV8wG5Aow8v3dDyWk2E54ndpZ5N9heRFTjMtG+P9sV0bVnFWMF2IUx13RqnlSIPb13CG7rWkm2WztDRCD1PxWz4m9dx2Jr5kPRYeguVZpsmJZfTl5sgMznpkJz1m/6Aak3YhbObn8tGdJkoFfgLobzCqJk519sHXhWs5slNHtryDTcakhGeEaFu9UldO+rd5Nr7uhITYCemq4M8vhcw2o30kuxcQKYVXxXcnL+7Ay9z0Tx1knJvdnnNCOVJLAujqvNNfdKvPR8LlimaucswjDwXukTN90uPplTky+LWG7DofrYUham/No+8S0nhEtPycqsou1gsLvI6oVUz8rT3NIm3tn0HBOGQ8c21mPbg3qMlI2D7J7BUMvz3gAMkdcoiGEr6Gwh4x+7iyr8Yl1aGbn0oAq7rVoyTG4ee8TmwFoqeBJCk1x+vbN0RctFmSGlUmmRWJdr3ezJynugp9KOpgUMGsKv4rNsRPX3+/maqzWaF27B5SJwHSmVGSkIg9sf9iixELUaPHuRa0dtgQj68uNvM9hPzgrhneJoQTjAwKXpPfHldijO2BK6mn9qK9uR7xKhC4T7/b5mncLKk+q+vU+adFvs7Mr46CZEENqVxm0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAB3ZHMZABU9vcKGc3TRKyksNL7hXdQymJpHAzxub0a0FDfJMrU0eJ2GedfhBtBi8ohMvBanuQZRP4GVhPxQWmVpA/84MA/rIxhp7FX4d80u+yp6I/IVLZc1u5BQRC8fJU/ynm00AqpXv0C0Hj1dGHcxWSmn0n3zmTA0NtkN7p0B+06E0vUJ0skv61cJ8mmdC9T2+8lsxQHBMRZaklFfTMMTmoEqqCMn1XOGeAtPO5yZr6Bqozh+xty26mAXrVIEeMfPfDQRrvY/Q448sJO647aYA8GraVUSue46FHBYHsyqVIWi+Fc4Xs9fdBxzg1qlumz9+EmpK5WsrsXGYUWFFSqZfLOqS8Q7NdYee4QCkWr6QNsjIEhmvVvVEVfxH6kLsEB0lYK830CNlFCCqfN5GG2Y2nwwvNieTMeInhoO2jMx/4DEYTi3aWs4bSMKF3RjldA+xaUvyiXlbUWPrEC2fGZr7KUoU9gagrk5JM/HzDdZ9H9GOY5QyOFTSh72E4HmVOUQ3HQivsxTHmB7irpDbbJpHzz6WbNIirHifSpEQ1O5hPVLnUHsnRegmONEb1mu1JZXF8bu8gw1uKCVGLQ6JxLZEQxqy7tyOKF9Z5XJUuZqngmgVqqtvDdEnM17foWWvNsBhGj4ahc6JSn5KQKwPm/O1OoH6F5W+NL1uSF0Srnpw=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  
<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><xenc:CipherData><xenc:CipherValue>G5SUN6G0/AYBR0NyQsfAp0eqlf6XGO37E8p3VlpQmgjiheo7TXsOINk1t2Tycolsw+ncWyrchaVE6vwO26LLeUpLsxgQWDk8N/Ghomj6cJC8b9D6w8y37oGlv1SNoYAMoP1mTJQdee7O2TrfnvY3rFl57DcZGnwJOB8ijBJiS1c9Urr9aH0IbK3Vtvk5kvYRNH9RAOZCUtZYSpZJ7VVhhdBl2aitF3nUIhg/sVy5hPAMMjd7Dc3A04n8BCIwqn2pBAPgqtPwvuLsLs9YgjKAC3LvAkFv1fQoJMZXu0Go/Jh5waqAR51OlmNDjMO1vZ475x0ynQOeCvVyZluR4n8uoV1YpFc7/LuDQeN5mKiZm7ta1LFFfFsXgklylu5JxGwZqoubnmUd2XLXzErSlgu47yS5wLc0KC7uvpKJ/Q0VsqMmqYM8p3iNVpuWLTsWEtVG+bmPlPbbNlf0nDEqUKulZJTeM4PSUzkhMKUQG76KWSVPZ5lrMQI1knATDMv74HmaKD2z+UDkLplJ3lg2IOXp2Us3FiReghYzBNqlr5uw/ncd+j+OLmiCg5GlH9daumZ/NXZS4XVaXFWyDZRTtkXtUvpMmiGlhxGTDX1HGZD0EPBsUdi/INRKvKBcFlCpUSzq+yc92x8VTJsOzjm3aVizdoU/swBZxBJENeVM/PiiBRs=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></dsig:KeyInfo>
   <xenc:CipherData>
      <xenc:CipherValue>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</xenc:CipherValue>
   </xenc:CipherData>
</xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>
XML;

    /**
     * Signed with AbstractSamlTestCase::KEY_IDP_PRIVATE (SHA1)
     * @see AbstractSamlTestCase::MESSAGE_UNSIGNED_RESPONSE_WITH_UNSIGNED_UNENCRYPTED_ASSERTION
     */
    const MESSAGE_SIGNED_RESPONSE_WITH_UNSIGNED_UNENCRYPTED_ASSERTION = <<<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfx656e444c-c75e-edc7-45c2-01878435eb0a" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx656e444c-c75e-edc7-45c2-01878435eb0a"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>lmZsjWh+9GgEL4h/pCrHhlfhALQ=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>jB8s1stlI644nRejIDh26Qe+APNe1eznDVD17VD6iV7Vj3pJv/CxKJsI6iAXlN6uun6Us8QsUtayBAigeUT/p7Wgit0sQxo7XBtaJB74b4dT9cYsJNIyuLnhfFcUFBX11/Gx/hWtaOtSHadB9oXYz4ZA0Gma5iEPqWVub3TmD6I4lnrQnyaUIhVH0shGIkxGXTzowhVZRQ+0gL7Ip0lAgcX90Hg20GokxdrF9obwCKjXiY+enCG1F/11occddp8lN9r4l5LyqWWGIBQTHNRjh9YoQgCECqc6HW3ce5NTrn1/e5UjkzyCdqJ3fzFUzZPWoK4UlwpwK0y/jwKqyW3fSwOx2yRcpe9XWXHC82KcjGSEagaPRLNAs2uVJ0p1Oovrh4Aj+J6xnDCwwsekwC6gZzm7y5t9qCulcHEA+razWpmJhz4uimTeEeXAvZrOqC8uPzEZ77PETS90FIaj4Iq+m6x1Zfondzp3mO3Ujyw4atIsgjxgZNYr1EyW+t3EuHUdxMXnUhYXEreMtq+H77Ef/WLmHD4mwVGRwEgFrubhS8mXOf/au7VWtVbqgCb60vnF9PGy/I9clvwu9/c+bxIg5OE/fTHs+km1UFhqn1r4qntrttndC9XMxAzShYYrAtjP0MxFYm+/CNRwSwheIU5mpJMy3zaz1TAb4HrXj8QMc9U=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIFYjCCA0oCCQCbWD6pJkNM8DANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJDQTEMMAoGA1UECAwDZm9vMQwwCgYDVQQHDANiYXIxDDAKBgNVBAoMA2JhejEMMAoGA1UECwwDcXV4MQwwCgYDVQQDDANpZHAxHjAcBgkqhkiG9w0BCQEWD2lkcEBleGFtcGxlLmNvbTAeFw0yMTAxMTAwMTM5MTFaFw0yMTAyMDkwMTM5MTFaMHMxCzAJBgNVBAYTAkNBMQwwCgYDVQQIDANmb28xDDAKBgNVBAcMA2JhcjEMMAoGA1UECgwDYmF6MQwwCgYDVQQLDANxdXgxDDAKBgNVBAMMA2lkcDEeMBwGCSqGSIb3DQEJARYPaWRwQGV4YW1wbGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAt/7Xc5FzcUXbStaEVyYyDIfNRmjXEo4O9dFlZUOgoerFir2igDafkWdUuejCn8aWkNFV8wG5Aow8v3dDyWk2E54ndpZ5N9heRFTjMtG+P9sV0bVnFWMF2IUx13RqnlSIPb13CG7rWkm2WztDRCD1PxWz4m9dx2Jr5kPRYeguVZpsmJZfTl5sgMznpkJz1m/6Aak3YhbObn8tGdJkoFfgLobzCqJk519sHXhWs5slNHtryDTcakhGeEaFu9UldO+rd5Nr7uhITYCemq4M8vhcw2o30kuxcQKYVXxXcnL+7Ay9z0Tx1knJvdnnNCOVJLAujqvNNfdKvPR8LlimaucswjDwXukTN90uPplTky+LWG7DofrYUham/No+8S0nhEtPycqsou1gsLvI6oVUz8rT3NIm3tn0HBOGQ8c21mPbg3qMlI2D7J7BUMvz3gAMkdcoiGEr6Gwh4x+7iyr8Yl1aGbn0oAq7rVoyTG4ee8TmwFoqeBJCk1x+vbN0RctFmSGlUmmRWJdr3ezJynugp9KOpgUMGsKv4rNsRPX3+/maqzWaF27B5SJwHSmVGSkIg9sf9iixELUaPHuRa0dtgQj68uNvM9hPzgrhneJoQTjAwKXpPfHldijO2BK6mn9qK9uR7xKhC4T7/b5mncLKk+q+vU+adFvs7Mr46CZEENqVxm0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAB3ZHMZABU9vcKGc3TRKyksNL7hXdQymJpHAzxub0a0FDfJMrU0eJ2GedfhBtBi8ohMvBanuQZRP4GVhPxQWmVpA/84MA/rIxhp7FX4d80u+yp6I/IVLZc1u5BQRC8fJU/ynm00AqpXv0C0Hj1dGHcxWSmn0n3zmTA0NtkN7p0B+06E0vUJ0skv61cJ8mmdC9T2+8lsxQHBMRZaklFfTMMTmoEqqCMn1XOGeAtPO5yZr6Bqozh+xty26mAXrVIEeMfPfDQRrvY/Q448sJO647aYA8GraVUSue46FHBYHsyqVIWi+Fc4Xs9fdBxzg1qlumz9+EmpK5WsrsXGYUWFFSqZfLOqS8Q7NdYee4QCkWr6QNsjIEhmvVvVEVfxH6kLsEB0lYK830CNlFCCqfN5GG2Y2nwwvNieTMeInhoO2jMx/4DEYTi3aWs4bSMKF3RjldA+xaUvyiXlbUWPrEC2fGZr7KUoU9gagrk5JM/HzDdZ9H9GOY5QyOFTSh72E4HmVOUQ3HQivsxTHmB7irpDbbJpHzz6WbNIirHifSpEQ1O5hPVLnUHsnRegmONEb1mu1JZXF8bu8gw1uKCVGLQ6JxLZEQxqy7tyOKF9Z5XJUuZqngmgVqqtvDdEnM17foWWvNsBhGj4ahc6JSn5KQKwPm/O1OoH6F5W+NL1uSF0Srnpw=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
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
     * Signed with AbstractSamlTestCase::KEY_IDP_PRIVATE (SHA1)
     * Encrypted with AbstractSamlTestCase::KEY_SP_X509 (AES128)
     * @see AbstractSamlTestCase::MESSAGE_UNSIGNED_RESPONSE_WITH_UNSIGNED_UNENCRYPTED_ASSERTION
     */
    const MESSAGE_UNSIGNED_RESPONSE_WITH_SIGNED_ENCRYPTED_ASSERTION = <<<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  
<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><xenc:CipherData><xenc:CipherValue>ptSEceuv9mcR5YbghaVh+OkfLe6xwE3rnAWlgqCbMpk8NAq5Cs3LUE78xPvdI1AQyHIiSYGuwOIhofOkl1Gkc2Y/lJ7G3Y4vprHPJ+KMwDS3WHSFEfGvR3fM0mmp0HswT5fSVJ1IImWgdQdtrM+yihbKuwP2wwUwPwdTVakMjXUrBKKcDNjos87dY18hYVXca/+MEc6e6T5/5/K7yuCujiqFs9hF3J82aLWz5a4rKwhpz3KqMxdUPM4woGKE+94k+ON7eU3d1tkufg+NXVUu7n05gKxafDZooiAVpGaRepSrgkYiyUYlWX1NXLCBb6EmmOc71sS8USq59f2FPcu8ac33/X80cAJgbmuLvfEWZGeaI/EcGx1WtIGUb8TfqDnGmJKuo62baD5XVYKvfhOCTmHQTUBLhQNGF/XKN0R6P6iYszsEcxO4ZAXLDfH6v/bm5swYQI/KEg/g26AGw5W0332LXVnSUsMHKbpR39sgu+nDxrhSTQbHcG/5xpOg9Hz/Vjx9R7qQi8aSAoVmxIeuzc1Ziv/+1n9obeIkW0GFtXvbYnfsgSgYa3IRWUIjenYtevprmGU0BT87qTZ4QWlfTgTSidDFeGlwbuCvDD4M+9ifB35OoDaSFfoAlTVE1YL8UiyhzhFjE3pMTbZJyUojeqlctTC65YBiA3yRtdMeIqo=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></dsig:KeyInfo>
   <xenc:CipherData>
      <xenc:CipherValue>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</xenc:CipherValue>
   </xenc:CipherData>
</xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>
XML;

    /**
     * Signed with AbstractSamlTestCase::KEY_IDP_PRIVATE (SHA1)
     * @see AbstractSamlTestCase::MESSAGE_UNSIGNED_RESPONSE_WITH_UNSIGNED_UNENCRYPTED_ASSERTION
     */
    const MESSAGE_UNSIGNED_RESPONSE_WITH_SIGNED_UNENCRYPTED_ASSERTION = <<<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="pfx6134eddd-9f42-ad50-6dfa-d29602bfe84e" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx6134eddd-9f42-ad50-6dfa-d29602bfe84e"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>JuG7cVRxAlHsP1PRndROQzTS5oY=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>KyevpNuwicQPEd31fdpP16Rw/sL1OAMdfKsNiMHRkyO/fovSriWkE1c/RXcIaRLHOPm9LiWOjJDySVmTGO+1ax01uUUu+zT8N2f/F3LcG52PixY/1oLWsOz+A/pOsQE50satRpipigQZbRs9SHplUbPijmxGVq7Mrzo3lPJs49iYUtYcBpCrbOC2BSvccMQlgPH8uu5ZcLhZ7WFvv9POtO2cLQIWDMuCDY90f4o3E2KMXbAASY3KKoge94QAwxbj0CF7+0Pgo9Vgk6W32MulqCdGdyocdCiETy1ZD7MwU6jCflIiocBPqUUch7rlktZ914+9b7dyNdDRsRdXxynu1j80JqvpcQvZYWtGd3LNGSCrdYb8GsdTbNQAw2QZRHj4ddvYr7K1Dq//LpgpsIA9r28nr7cc6UNdqd9PPTJcoM7leSkAE546AfuGzUnK/JRV7X15/7SkzV5NgkO0EuGnx6xMKiJQBW8YGtWPzbB+9Mcibimqoye2o3QSMc2I4n+wiay/nT47jOAFou/PR1/rZWK6KWPXvKJ7MNBewdcGXxA+VkOhWxkQfxHGKSAHJq7YO3ZXsI6nzhJAkPIceRZdz7Sh+caIEDo+myXhzWuevsi8YzU/+eQS9g6gXqoFtLHIrP2Lq9o5EwO/znszpOee3WsDZIH27YLUr6bJ3qE/Pm0=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIFYjCCA0oCCQCbWD6pJkNM8DANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJDQTEMMAoGA1UECAwDZm9vMQwwCgYDVQQHDANiYXIxDDAKBgNVBAoMA2JhejEMMAoGA1UECwwDcXV4MQwwCgYDVQQDDANpZHAxHjAcBgkqhkiG9w0BCQEWD2lkcEBleGFtcGxlLmNvbTAeFw0yMTAxMTAwMTM5MTFaFw0yMTAyMDkwMTM5MTFaMHMxCzAJBgNVBAYTAkNBMQwwCgYDVQQIDANmb28xDDAKBgNVBAcMA2JhcjEMMAoGA1UECgwDYmF6MQwwCgYDVQQLDANxdXgxDDAKBgNVBAMMA2lkcDEeMBwGCSqGSIb3DQEJARYPaWRwQGV4YW1wbGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAt/7Xc5FzcUXbStaEVyYyDIfNRmjXEo4O9dFlZUOgoerFir2igDafkWdUuejCn8aWkNFV8wG5Aow8v3dDyWk2E54ndpZ5N9heRFTjMtG+P9sV0bVnFWMF2IUx13RqnlSIPb13CG7rWkm2WztDRCD1PxWz4m9dx2Jr5kPRYeguVZpsmJZfTl5sgMznpkJz1m/6Aak3YhbObn8tGdJkoFfgLobzCqJk519sHXhWs5slNHtryDTcakhGeEaFu9UldO+rd5Nr7uhITYCemq4M8vhcw2o30kuxcQKYVXxXcnL+7Ay9z0Tx1knJvdnnNCOVJLAujqvNNfdKvPR8LlimaucswjDwXukTN90uPplTky+LWG7DofrYUham/No+8S0nhEtPycqsou1gsLvI6oVUz8rT3NIm3tn0HBOGQ8c21mPbg3qMlI2D7J7BUMvz3gAMkdcoiGEr6Gwh4x+7iyr8Yl1aGbn0oAq7rVoyTG4ee8TmwFoqeBJCk1x+vbN0RctFmSGlUmmRWJdr3ezJynugp9KOpgUMGsKv4rNsRPX3+/maqzWaF27B5SJwHSmVGSkIg9sf9iixELUaPHuRa0dtgQj68uNvM9hPzgrhneJoQTjAwKXpPfHldijO2BK6mn9qK9uR7xKhC4T7/b5mncLKk+q+vU+adFvs7Mr46CZEENqVxm0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAB3ZHMZABU9vcKGc3TRKyksNL7hXdQymJpHAzxub0a0FDfJMrU0eJ2GedfhBtBi8ohMvBanuQZRP4GVhPxQWmVpA/84MA/rIxhp7FX4d80u+yp6I/IVLZc1u5BQRC8fJU/ynm00AqpXv0C0Hj1dGHcxWSmn0n3zmTA0NtkN7p0B+06E0vUJ0skv61cJ8mmdC9T2+8lsxQHBMRZaklFfTMMTmoEqqCMn1XOGeAtPO5yZr6Bqozh+xty26mAXrVIEeMfPfDQRrvY/Q448sJO647aYA8GraVUSue46FHBYHsyqVIWi+Fc4Xs9fdBxzg1qlumz9+EmpK5WsrsXGYUWFFSqZfLOqS8Q7NdYee4QCkWr6QNsjIEhmvVvVEVfxH6kLsEB0lYK830CNlFCCqfN5GG2Y2nwwvNieTMeInhoO2jMx/4DEYTi3aWs4bSMKF3RjldA+xaUvyiXlbUWPrEC2fGZr7KUoU9gagrk5JM/HzDdZ9H9GOY5QyOFTSh72E4HmVOUQ3HQivsxTHmB7irpDbbJpHzz6WbNIirHifSpEQ1O5hPVLnUHsnRegmONEb1mu1JZXF8bu8gw1uKCVGLQ6JxLZEQxqy7tyOKF9Z5XJUuZqngmgVqqtvDdEnM17foWWvNsBhGj4ahc6JSn5KQKwPm/O1OoH6F5W+NL1uSF0Srnpw=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
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
     * Encrypted with AbstractSamlTestCase::KEY_SP_X509 (AES128)
     * @see AbstractSamlTestCase::MESSAGE_UNSIGNED_RESPONSE_WITH_UNSIGNED_UNENCRYPTED_ASSERTION
     */
    const MESSAGE_UNSIGNED_RESPONSE_WITH_UNSIGNED_ENCRYPTED_ASSERTION = <<<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  
<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><xenc:CipherData><xenc:CipherValue>U3GQs2opb316j6XMdZ54t0hKKuPsNMBBFO1ppmNvNkOCDEXTUGzypymyEgVeZqQ83ZEAvjUM0iBFQh+SQCcpX+w80UjhG/JK1rRsorKqxg7icwT8pk0aiwF1euUbf6Gm8iWPwMFArGkAHEMUxKvo7xBORDQaru7vzmDhoquNY1AixQ9juNCQ3pc6zsF4v2jTwtICtdrSOLfJuuLPkh9kXVmeEOnHumoelGrGW1iht1Ws7o+1xN+S0oM+0ujqjbEmJS/JtvCG1esVEpOjoqD5AlEWGnOXaXKholCmy1jDlg3QNNXpXkKOZ7hzNbBDqJNWRATNEXGGQ5AQixSONNdGBPzewrUJDNUErX/jvuQ1bygvyp4Xep4PE/1yQUfMAKTAFezUV1q6iVLWEHpeXo5zzx5Vu4GTQcAJmd22F5RPCjj6Ejj42WSO1xHGQFejQ7WMCgu/eB3fcTTY7Qo83uP3aIsj07/0xCUF+tfvN1+VZsm77EDG7pnTJmoNAvnNb6jxapnRiwwh4Rlc5Hphg7v+PfkG6m2bN0fwr66N5/PhU/tuwGJhkaXcsueBRWzhgUFTmilWtJi0bLB8YznDFim0K1pfxrCdlYr5GPvC2KnzYHwqhduNYHjR6e+RpMb0JdXj993+PiIYfMmnjebTDP4QoT3XuBjn2lI+6QfgNgQRkcM=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></dsig:KeyInfo>
   <xenc:CipherData>
      <xenc:CipherValue>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</xenc:CipherValue>
   </xenc:CipherData>
</xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>
XML;

    /**
     * @note (modethirteen, 20210110): signed redirect binding requests use an unsigned message body and add the signature when building the request URI in the test case
     * @return array
     * @throws NotSupportedException
     */
    public static function isPostHttpMessage_isMessageSignatureRequired_isAssertionSignatureRequired_isAssertionEncryptionRequired_isSuccessExpected_message_SuccessProvider() : array {
        $args = [];
        foreach([
            'POST binding' => true,
            'Redirect binding' => false
        ] as $bindingLabel => $isPostHttpMessage) {
            foreach([
                'with signed (required) message' => self::CASE_FULFILLED_REQUIRED,
                'with signed (not required) message' => self::CASE_FULFILLED_NOT_REQUIRED,
                'with unsigned (required) message' => self::CASE_UNFULFILLED_REQUIRED,
                'with unsigned (not required) message' => self::CASE_UNFULFILLED_NOT_REQUIRED
            ] as $messageSignatureLabel => $messageSignatureCase) {
                foreach([
                    'with signed (required)' => self::CASE_FULFILLED_REQUIRED,
                    'with signed (not required)' => self::CASE_FULFILLED_NOT_REQUIRED,
                    'with unsigned (required)' => self::CASE_UNFULFILLED_REQUIRED,
                    'with unsigned (not required)' => self::CASE_UNFULFILLED_NOT_REQUIRED
                ] as $assertionSignatureLabel => $assertionSignatureCase) {
                    foreach([
                        'and encrypted (required) assertion' => self::CASE_FULFILLED_REQUIRED,
                        'and encrypted (not required) assertion' => self::CASE_FULFILLED_NOT_REQUIRED,
                        'and unencrypted (required) assertion' => self::CASE_UNFULFILLED_REQUIRED,
                        'and unencrypted (not required) assertion' => self::CASE_UNFULFILLED_NOT_REQUIRED
                    ] as $assertionEncryptionLabel => $assertionEncryptionCase) {

                        // calculate requirements
                        $isMessageSignatureRequired = self::isCase($messageSignatureCase, [self::CASE_FULFILLED_REQUIRED, self::CASE_UNFULFILLED_REQUIRED]);
                        $isAssertionSignatureRequired =  self::isCase($assertionSignatureCase, [self::CASE_FULFILLED_REQUIRED, self::CASE_UNFULFILLED_REQUIRED]);
                        $isAssertionEncryptionRequired = self::isCase($assertionEncryptionCase, [self::CASE_FULFILLED_REQUIRED, self::CASE_UNFULFILLED_REQUIRED]);

                        // select message
                        $isMessageSigned = self::isCase($messageSignatureCase, [self::CASE_FULFILLED_REQUIRED, self::CASE_FULFILLED_NOT_REQUIRED]);
                        $isAssertionSigned = self::isCase($assertionSignatureCase, [self::CASE_FULFILLED_REQUIRED, self::CASE_FULFILLED_NOT_REQUIRED]);
                        $isAssertionEncrypted = self::isCase($assertionEncryptionCase, [self::CASE_FULFILLED_REQUIRED, self::CASE_FULFILLED_NOT_REQUIRED]);
                        switch(true) {
                            case $isMessageSigned && $isAssertionSigned && $isAssertionEncrypted:
                                $message = self::MESSAGE_SIGNED_RESPONSE_WITH_SIGNED_ENCRYPTED_ASSERTION;
                                break;
                            case $isMessageSigned && $isAssertionSigned && !$isAssertionEncrypted:
                                $message = self::MESSAGE_SIGNED_RESPONSE_WITH_SIGNED_UNENCRYPTED_ASSERTION;
                                break;
                            case $isMessageSigned && !$isAssertionSigned && $isAssertionEncrypted:
                                $message = self::MESSAGE_SIGNED_RESPONSE_WITH_UNSIGNED_ENCRYPTED_ASSERTION;
                                break;
                            case $isMessageSigned && !$isAssertionSigned && !$isAssertionEncrypted:
                                $message = self::MESSAGE_SIGNED_RESPONSE_WITH_UNSIGNED_UNENCRYPTED_ASSERTION;
                                break;
                            case !$isMessageSigned && $isAssertionSigned && !$isAssertionEncrypted:
                                $message = self::MESSAGE_UNSIGNED_RESPONSE_WITH_SIGNED_UNENCRYPTED_ASSERTION;
                                break;
                            case !$isMessageSigned && $isAssertionSigned && $isAssertionEncrypted:
                                $message = self::MESSAGE_UNSIGNED_RESPONSE_WITH_SIGNED_ENCRYPTED_ASSERTION;
                                break;
                            case !$isMessageSigned && !$isAssertionSigned && !$isAssertionEncrypted:
                                $message = self::MESSAGE_UNSIGNED_RESPONSE_WITH_UNSIGNED_UNENCRYPTED_ASSERTION;
                                break;
                            case !$isMessageSigned && !$isAssertionSigned && $isAssertionEncrypted:
                                $message = self::MESSAGE_UNSIGNED_RESPONSE_WITH_UNSIGNED_ENCRYPTED_ASSERTION;
                                break;
                            default:
                                throw new NotSupportedException('unsupported case');
                        }

                        // add test case to data provider
                        $isSuccessExpected = !self::isCase($messageSignatureCase | $assertionSignatureCase | $assertionEncryptionCase, [self::CASE_UNFULFILLED_REQUIRED]);
                        $args["{$bindingLabel} {$messageSignatureLabel} {$assertionSignatureLabel} {$assertionEncryptionLabel}"] = [
                            $isPostHttpMessage,
                            $isMessageSigned,
                            $isMessageSignatureRequired,
                            $isAssertionSigned,
                            $isAssertionSignatureRequired,
                            $isAssertionEncrypted,
                            $isAssertionEncryptionRequired,
                            $isSuccessExpected,
                            $message
                        ];
                    }
                }
            }
        }
        return $args;
    }

    /**
     * @param int $case
     * @param int[] $checks - check if $case contains any of these case situations
     * @return bool
     */
    private static function isCase(int $case, array $checks) : bool {
        foreach($checks as $check) {
            if(($case & $check) === $check) {
                return true;
            }
        }
        return false;
    }

    /**
     * @todo (modethirteen, 20200110): test encrypted Assertion/Subject/@NameID
     * @dataProvider isPostHttpMessage_isMessageSignatureRequired_isAssertionSignatureRequired_isAssertionEncryptionRequired_isSuccessExpected_message_SuccessProvider
     * @test
     * @param bool $isPostHttpMessage
     * @param bool $isMessageSigned
     * @param bool $isMessageSignatureRequired
     * @param bool $isAssertionSigned
     * @param bool $isAssertionSignatureRequired
     * @param bool $isAssertionEncrypted
     * @param bool $isAssertionEncryptionRequired
     * @param bool $isSuccessExpected
     * @param string $message
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     * @throws MalformedUriException
     * @throws SamlFlowServiceException
     * @throws SamlCannotGenerateSignatureException
     * @throws SamlCannotLoadCryptoKeyException
     */
    public function Can_process_message(
        bool $isPostHttpMessage,
        bool $isMessageSigned,
        bool $isMessageSignatureRequired,
        bool $isAssertionSigned,
        bool $isAssertionSignatureRequired,
        bool $isAssertionEncrypted,
        bool $isAssertionEncryptionRequired,
        bool $isSuccessExpected,
        string $message
    ) : void {
        if($isPostHttpMessage && $isMessageSigned && $isAssertionEncrypted) {

            // TODO (modethirteen, 20210112): handle POST binding signed message and encrypted assertion
            $isSuccessExpected = false;
        }

        // idp keys are needed to both sign redirect binding requests as well as validate all signed requests
        $identityProviderKeyPair = static::newIdentityProviderCryptoKeyPairFactory()
            ->withDigestAlgorithm('sha1')
            ->newCryptoKeyPair();

        // request
        $uri = SamlHttpMessageUri::newFromString('http://sp.example.com/demo1/index.php?acs');
        if($isPostHttpMessage) {
            $request = $this->newHttpPostRequest($uri, new XArray([
                'RelayState' => 'https://app.example.com/dashboard',
                'SAMLResponse' => static::getPostEncodedHttpMessage($message)
            ]));
        } else {
            $uri = $uri->with('RelayState', 'https://app.example.com/dashboard');
            if($isMessageSigned || $isAssertionSigned) {

                // redirect message is signed: swap out message for unsigned XML and generate a URI signature instead
                $uri = $uri
                    ->with('SAMLResponse', static::getRedirectEncodedDeflatedHttpMessage(
                        $isAssertionEncrypted
                            ? self::MESSAGE_UNSIGNED_RESPONSE_WITH_UNSIGNED_ENCRYPTED_ASSERTION
                            : self::MESSAGE_UNSIGNED_RESPONSE_WITH_UNSIGNED_UNENCRYPTED_ASSERTION
                    ))
                    ->withSignature($identityProviderKeyPair->getPrivateKey());

                // one signature handles both cases
                $isMessageSigned = true;
                $isAssertionSigned = true;
            } else {
                $uri = $uri->with('SAMLResponse', static::getRedirectEncodedDeflatedHttpMessage($message));
            }
            $request = $this->newHttpGetRequest($uri);
        }
        $isRequestMissingRequiredSignature = ($isMessageSignatureRequired && !$isMessageSigned) || ($isAssertionSignatureRequired && !$isAssertionSigned);

        // event dispatcher
        /** @var SamlAuthnResponseFlowEvent[] $events */
        $events = [];
        $eventDispatcher = $this->newMock(EventDispatcherInterface::class);
        if($isSuccessExpected) {
            $eventDispatcher->expects(static::atLeastOnce())
                ->method('dispatch')
                ->willReturnCallback(function(object $event) use (&$events) {
                    $events[] = $event;
                });
        }

        // saml configuration
        $saml = $this->newMock(SamlConfigurationInterface::class);
        if($isSuccessExpected) {

            // these values are only needed once message processing/validation occurs (after signature and encryption requirement checks)
            $saml->expects(static::atLeastOnce())
                ->method('getAllowedClockDrift')
                ->willReturn(SamlFlowService::ALLOWED_CLOCK_DRIFT);
            $saml->expects(static::atLeastOnce())
                ->method('getNameIdFormats')
                ->willReturn([HttpMessageInterface::NAMEID_TRANSIENT]);
            $saml->expects(static::atLeastOnce())
                ->method('getServiceProviderEntityId')
                ->willReturn('http://sp.example.com/demo1/metadata.php');
            $saml->expects(static::atLeastOnce())
                ->method('getIdentityProviderEntityId')
                ->willReturn('http://idp.example.com/metadata.php');
        }
        if(

            // idp x.509 only necessary if message or assertion is signed
            ($isMessageSigned || $isAssertionSigned) &&

            // ...and will not be loaded if a required signature is not detected
            !$isRequestMissingRequiredSignature
        ) {
            $saml->expects( static::atLeastOnce())
                ->method('getIdentityProviderX509Certificate')
                ->willReturn($identityProviderKeyPair->getPublicKey());
        }
        if($isAssertionEncrypted) {
            $saml->expects(static::atLeastOnce())
                ->method('getServiceProviderPrivateKey')
                ->willReturn(static::newServiceProviderCryptoKeyPairFactory()
                    ->newCryptoKeyPair()
                    ->getPrivateKey()
                );
        }
        if(
            // if assertion is unencrypted, check if encryption is required
            !$isAssertionEncrypted &&

            // if message/assertion requires signature, and either are unsigned, the encryption requirement will not be checked
            !$isRequestMissingRequiredSignature
        ) {
            $saml->expects(static::atLeastOnce())
                ->method('isAssertionEncryptionRequired')
                ->willReturn($isAssertionEncryptionRequired);
        }
        $saml->expects(static::atLeastOnce())
            ->method('isAssertionSignatureRequired')
            ->willReturn($isAssertionSignatureRequired);
        $saml->expects(static::atLeastOnce())
            ->method('isMessageSignatureRequired')
            ->willReturn($isMessageSignatureRequired);
        $saml->expects(static::atLeastOnce())
            ->method('isStrictValidationRequired')
            ->willReturn(true);

        // session
        $dateTime = new DateTimeImmutable('2018-07-12T14:38:55.529Z');

        // bootstrap service
        /** @var EventDispatcherInterface $eventDispatcher */
        /** @var ContextLoggerInterface $logger */
        /** @var UuidFactoryInterface $uuidFactory */
        /** @var SessionIndexRegistryInterface $sessionIndexRegistry */
        /** @var SamlConfigurationInterface $saml */
        $logger = $this->newMock(ContextLoggerInterface::class);
        $uuidFactory = $this->newMock(UuidFactoryInterface::class);
        $sessionIndexRegistry = $this->newMock(SessionIndexRegistryInterface::class);
        $service = new SamlFlowService(
            $saml,
            $dateTime,
            $logger,
            $uuidFactory,
            $eventDispatcher,
            static::newDocumentFactory(),
            $sessionIndexRegistry
        );
        if($isSuccessExpected) {

            // act
            $result = $service->getAuthenticatedUri($request);

            // assert
            static::assertTrue(MockPlug::verifyAll());
            static::assertEquals('https://app.example.com/dashboard', $result->toString());
            static::assertCount(1, $events);
            $event = $events[0];
            static::assertEquals(1531406335, $event->getDateTime()->getTimestamp());
            static::assertEquals('_be9967abd904ddcae3c0eb4189adbe3f71e327cf93', $event->getSessionIndex());
            static::assertEquals([
                'uid' => 'test',
                'mail' => 'test@example.com',
                'eduPersonAffiliation' => [
                    'users',
                    'examplerole1'
                ]
            ], $event->getClaims()->toArray());
            static::assertEquals('_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7', $event->getClaims()->getUsername());
        } else {

            // assert
            static::expectException(AuthServiceException::class);

            // act
            $service->getAuthenticatedUri($request);
        }
    }
}
