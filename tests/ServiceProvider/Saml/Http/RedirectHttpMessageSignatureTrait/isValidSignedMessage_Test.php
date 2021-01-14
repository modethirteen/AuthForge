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
namespace modethirteen\AuthForge\Tests\ServiceProvider\Saml\Http\RedirectHttpMessageSignatureTrait;

use modethirteen\AuthForge\Common\Exception\ServerRequestInterfaceParsedBodyException;
use modethirteen\AuthForge\Common\Http\ServerRequestEx;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Http\RedirectHttpMessageSignatureTrait;
use modethirteen\AuthForge\Tests\ServiceProvider\Saml\AbstractSamlTestCase;
use modethirteen\Crypto\Exception\CryptoKeyCannotParseCryptoKeyTextException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryCannotConstructCryptoKeyException;
use modethirteen\Http\Exception\MalformedUriException;
use modethirteen\Http\XUri;

class isValidSignedMessage_Test extends AbstractSamlTestCase {
    use RedirectHttpMessageSignatureTrait;

    const KEY_IDP_PRIVATE = <<<TEXT
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

    const KEY_IDP_X509 = <<<TEXT
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
     * @test
     * @throws MalformedUriException
     * @throws SamlCannotLoadCryptoKeyException
     * @throws ServerRequestInterfaceParsedBodyException
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     */
    public function Can_get_signed_request_query() : void {

        // arrange
        $uri = XUri::newFromString('https://example.com/@app/saml/slo')
            ->with('SAMLResponse', 'fZJRa8IwEMffB/sOJe+2SVuaNljZmGMITmGKD3uRmF5moU1CLwU//mo3h/PBx/tffr87jkxRto0TS/tle/8B6KxBCE5tY1CMrZL0nRFWYo3CyBZQeCU2z+9LEYdUuM56q2xDrpD7hESEztfWkGAxL8k+UwlPeJzHmlLOYwo8yTTVKY1zDVDl6lAchqJgigQ76HAgSzKIBhyxh4VBL40fIsrSCeUTlm8pEywRNPskwRzQ10b6kTp670QUwUm2roFQ2TZ6ks5F56UjbOygNJcTbG1J1qvX5fptsdrHrNIFk3nBM57zQiuqeaUzydKCqoxSqnKWpWlFZo8PQTA9+8S4XTf7nVlXLrye24KXlfQydEc3ja6BP4MTGy99j2Nyk73YCoKdbHq4f2wcX4tNrxQgkujHHt3oL8H/TzD7Bg==')
            ->with('Signature',  'NGwawN21IrelGtFudICTC59prrp6GE4vfI9znwYVbH0JRS4tKGoXTAs6xQ85yB7gPAZ6BgM5uc0BDxm+xNWMVRUjQxKojfIgLj7Th4trrFzNAHbkiXm7wajOsMOtxlRCEfx0huuo52ghBaxqiXq4tcYWV1qUj/vGjME5KOCVt2E=')
            ->with('SigAlg', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')
            ->with('RelayState', 'https://example.com/foo');
        $certificate = static::newIdentityProviderCryptoKeyPairFactory()
            ->newCryptoKeyPair()
            ->getPublicKey();
        $request = $this->newMock(ServerRequestEx::class);
        $request->expects(static::atLeastOnce())
            ->method('getUri')
            ->willReturn($uri);
        $request->expects(static::atLeastOnce())
            ->method('getParam')
            ->willReturnCallback(function(string $param) use ($uri) : ?string {
                return $uri->getQueryParam($param);
            });

        // act
        /** @var ServerRequestEx $request */
        $result = $this->isValidSignedMessage($certificate, $request);

        // assert
        static::assertTrue($result);
    }

    /**
     * @test
     * @throws MalformedUriException
     * @throws SamlCannotLoadCryptoKeyException
     * @throws ServerRequestInterfaceParsedBodyException
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     */
    public function Can_get_signed_response_query() : void {

        // arrange
        $uri = XUri::newFromString('https://example.com/@app/saml/slo')
            ->with('SAMLRequest', 'hZJfS8MwFMXfBb9DyfvapK39E7aCMJXC3NSKD75ISG+2QJvUJJV9fNtuzOnDfMu9ub+Tew6ZW9Y2HV3pre7dC3z2YJ23bxtl6XSzQL1RVDMrLVWsBUsdp9Xt44qGPqad0U5z3aAz5DLBrAXjpFbIK5cLtFnfrTYP5fojJLXICcvyNEmzNBcci7QWCSNxjnmCMeYZSeK4Rt4bGDvwCzTIDSLW9lAq65hyQwuTeIbTGcleMaEkojh5R95y8CQVcxO1c66jQSDrzoc9a7sGfK7boJJq28AhhgrMl+Tgd7sOFddXnjcffdHpKVMcBexvvoZWk6AFx2rm2IjOg3PqR2Y9ZFIuveppPDz3rJFCgjkt9q8u8u61aZm7nPPYkfVMTKPUGaasBOVQcUpc5CHnJItimMKOIOc4F3EWCg4ZxlHKkvCGQHr0cVh78HGo/3yZ4hs=')
            ->with('Signature',  'gJHeJDa4pBlLB72OJ69z0zmFFTXCRKVqwMz9GDf/eyi2o56ToPrvbrzhhF+sbiJjCAKHh71OS1iafD2ogc5OKpj30cTAxYOGKsJRyRwUCDghfIZflzx3zQmkyvQj5u9RQV0gP6lkGIFp/9VpmQlg1X4NyVlhy1YAF/3EQ8YUEB0=')
            ->with('SigAlg', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')
            ->with('RelayState', 'https://example.com/bar');
        $certificate = static::newIdentityProviderCryptoKeyPairFactory()
            ->newCryptoKeyPair()
            ->getPublicKey();
        $request = $this->newMock(ServerRequestEx::class);
        $request->expects(static::atLeastOnce())
            ->method('getUri')
            ->willReturn($uri);
        $request->expects(static::atLeastOnce())
            ->method('getParam')
            ->willReturnCallback(function(string $param) use ($uri) : ?string {
                return $uri->getQueryParam($param);
            });

        // act
        /** @var ServerRequestEx $request */
        $result = $this->isValidSignedMessage($certificate, $request);

        // assert
        static::assertTrue($result);
    }
}
