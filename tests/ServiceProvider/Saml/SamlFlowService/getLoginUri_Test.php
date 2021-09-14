<?php
/** @noinspection CheckTagEmptyBody */
declare(strict_types=1);
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
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentCannotWriteTextException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlFlowServiceException;
use modethirteen\AuthForge\ServiceProvider\Saml\Http\HttpMessageInterface;
use modethirteen\AuthForge\ServiceProvider\Saml\SamlConfigurationInterface;
use modethirteen\AuthForge\ServiceProvider\Saml\SamlFlowService;
use modethirteen\AuthForge\ServiceProvider\Saml\SessionIndexRegistryInterface;
use modethirteen\AuthForge\Tests\ServiceProvider\Saml\AbstractSamlTestCase;
use modethirteen\Crypto\Exception\CryptoKeyCannotParseCryptoKeyTextException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryCannotConstructCryptoKeyException;
use modethirteen\Http\Exception\MalformedUriException;
use modethirteen\Http\XUri;
use modethirteen\TypeEx\StringEx;
use Psr\EventDispatcher\EventDispatcherInterface;
use Ramsey\Uuid\UuidFactoryInterface;
use Ramsey\Uuid\UuidInterface;

class getLoginUri_Test extends AbstractSamlTestCase {

    /**
     * @return array
     */
    public static function isAuthnRequestSignatureRequired_isNameIdEncryptionRequired_nameIdFormat_expected_Provider() : array {
        return [
            'With signature and with NameID format and without NameID encryption' => [true, HttpMessageInterface::NAMEID_EMAIL_ADDRESS, false, <<<TEXT
https://idp.example.com/login?SAMLRequest=fZJfT8IwFMXf%2BRSk7wPKRhwNLJkQIwnqAuiDL6Z0F2jSP7O3U%2Fz2zg0CaKSPt%2Bd37jlpWyPkWhUsLf3OLOC9BPStdnX2Whlk9eWYlM4wy1EiM1wDMi%2FYMn2Ys36nxwpnvRVWkV%2FYdYojgvPSmgabTcdES5N7W4rdGx9u%2BjSkENB1jwZRHMYB34go4MM4jgY5F5sobLgXcFiZjEnlSVqNFWIJM4OeG1%2FNezQOejcB7a9oxMKYDQavDTqtmkrDfY3vvC%2BQdbsyLzqw57pQ0BFWd5XdykPE7NDztoopzfZ6vXUjQna%2FWmVB9rRcNSbpsfbEGiw1uCW4DyngeTE%2FhcDLDFwgSWq6fitWF3TJj%2FqvmPbDUfdcdgIL9ljlnE0zq6T4at9Zp7n%2Fvwbt0Hoi82BTSxloLlWa5w4QSTtVyn5OHHAPY%2BJdCSRpNl%2FuSVrH6fkXS74B&RelayState=https%3A%2F%2Fapp.example.com%2Fxyzzy&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=mtr2VC9AvWwyX0eJx4EPMCFgEMD8jyFmAPw4nA4oMMmm%2BD9mnHnasfJB0O%2BMcoendp75oXOPouG7XS%2FAKXhk52IPXT%2BA12UlBhaGXEESLJYUZ62lwas5ptv22JU%2FR7OEvkgu6bq3A9h343ZtXVtcZloTnDEUh6glAOO2Tw%2BQrXsxDctRLwNEBLIYCLXHhm5F96o9Ih3XggFOovOs5XFQSYKy68zJikMZHwYgMQYxvhRile8clNQNOillVONsdYQptf4Lao5UAfIBCdaZ6BkakDf3XoyD62VtOF3WixfPLg33umFi8bbcK4T5xgpe%2BNMbJ0rfdoxDFwS9dAncubPBz81Ye4zOq%2F9%2F7UdQMqPhKgzYkYZ5OjHjOU8e1%2FzcYOGaFEtBZLV7e%2BvGH61cZt1rytovGwDdzKY7iaXd5BX4kIkO%2BSoFsMKlMuHh%2By6UQ%2F3PPaKfuqdNDEivrmdcY36ytordLE2iBEApi3VSqzoGNzZbyBf9fqYFVq39kBZ88C6Y0IDGwYMknEN2x29G1D%2B0qHjcmTb3aYGwBtUeKt2%2B4bne7L8Z6g7zCFJKuohkTZ2pRphh9HhkqG3lTHi0DVOojG46uqMVT6LBrVYpgxtlGyNRKrNKjOWjiBWuYNDHESgSAmpdYsVe0D7bSzcckr8WyJ1yFt1R%2FRPHPQbmBdTkbvo%3D
TEXT
],
            'With signature and without NameID format and without NameID encryption' => [true, null, false, <<<TEXT
https://idp.example.com/login?SAMLRequest=fZHNTsMwEITveQqUu5M4PyJdNZEKPVCpiKoNHLgg13VbS7EdvA7q4xPiIihI3ePufKMZbTBFptoOZr076rV47wW64GaYk2o1wniswt5qMAwlgmZKIDgOm9njEtIogc4aZ7hpwz%2FYdYohCuuk0R5bzKtQSb1zpufHNzbZpzSjgtBtQkleZiVhe54TNinLvNgxvs8zz70Ii4NJFQ6eYeCtEHux0OiYdsM%2BoSVJbglNG5pDVkJRvHp0PjSVmrkRPzrXIcSx3HWRODHVtSLiRsWtOchzxNW5590QU%2BrD9XpbL0J4aJoVWT1tGm8y%2B659bzT2StiNsB%2BSi%2Bf18icEXmZgHMN6pMdfwVjQ1l%2Fq%2F2KaZtP4t2wEA7%2B7fHP9CQ%3D%3D&RelayState=https%3A%2F%2Fapp.example.com%2Fxyzzy&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=DDeZOR3sSPQbMCNlpfteQw79UnbfhVpx%2BJcwE5CR2MhMdZkmCryAcAgcQXeJgAJxKp6B8ZMblocgKy3omZQD9AlwsBMbJslZj9zRsea6QP1UHac1YCn4QQAqYkAX4o8rawlsksDliA7jRvKQD1IN%2FfNOuBz6cWHW2L8D2rglbMMQKk1GzaM9ih%2F1ZWUCj7G0WjCeWPaTqmOXNWLx%2BfxGV%2Ba7qk%2Bbi6%2F2Goxv8E0PMm8h1n%2Bqc2qy675B%2Bx8MmtxA6FLyPiGo10rZwVgEQemUN7oEIk%2FAyHo2VLifYAf5w2cZKMWFc%2Bd5CZp%2BcFXz%2Bj1lNimjhUk%2F1zhnD8h%2BDaGCfjgnOSUcIPzkIK6m4dqeForh1OTXXUtGnuI%2BLmNTjS3ZvbuoBkkvWXEoroDp3BCPSDX1EKShumb9tJ1iu1H9SJLJcfEWsTxnuwVKoIa3eBVUsZCqx0yb98DlRSbicJFcFfZ10b3StwfM2T6BPpNtJMDceHLz1gz1oliJrTWuNC4qVyq5UX8Cz2Ik%2FbBcbXvCzn99jBknMfFklQ0r%2BiaHjYYPTiozMI%2FlWsHHiRZZ7n%2Ft3sYj0Iy8KocLSHiqLGbdLyY4TURVByPBO%2FKia%2F6gQ7qo1PcmZc6p7GJGpZk5hwJfLqxedtiqOw37Ld1JtNk54qqpTezRIwFyFW70mYc48u0%3D
TEXT
],
            'With signature and with NameID format and with NameID encryption' => [true, HttpMessageInterface::NAMEID_TRANSIENT, true, <<<TEXT
https://idp.example.com/login?SAMLRequest=fZJfT8IwFMXf9ylI38f%2BEmfDlkyIkQSVwPTBF1O6O2iytbO3U%2Fj2jg0CaEIfb8%2Fv3HPSWmNkVVnTtDFbuYSvBtBYg%2FbsqlIi7S5j0mhJFUOBVLIKkBpOV%2BnznPpDl9ZaGcVVSf5gtymGCNoIJXtsNo1JJWRuVMO3n%2By%2B8L3AA9tbu54dRkFks4KHNruPonCUM16EQc%2B9g8bWJCatJ7F6K8QGZhINk6adu15ku3e252deSIOIjkYfPTptmwrJTIdvjamROo7I6yHsWFWXMOSqckq1EceIi2PPhzamkJvb9da9COlTli3sxesq603SU%2B2JkthUoFegvwWHt%2BX8HAKvMzCOJOno7q1oV1AnB%2FV%2FsecHY%2BdSdgZr%2BtLmnE0XqhR8P3hUumLmdo3DROR20UkpSK73tYGcDNKyVD8TDcxATIxugCT92usliXWaXv6v5Bc%3D&RelayState=https%3A%2F%2Fapp.example.com%2Fxyzzy&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=wZ%2FqBLST0xg7n7JlzLKEXJPDZUbkrhZPBAkiD2Sj4z%2BYlk%2BfnYPSwkTVt%2Fvzx3uH9A91PCrGjw2gpOo%2FTvQXIIMoeJkcxwI0uGvkg71Tc3BEouhFSJCrVFwHiaoUUl58th7jPq2maIY0lcoyBY%2BKYqdePVY0OiPpcqKltH4PLQ1Z6CssEZhCfRhue51Hx9J%2FdE8uvVJxekWuvT17VGlY5Qv2T5HIXlMz9hFPg%2BrWu6Axxfu0tEPXFZxtG49h%2FRm5tc55YKjT4WVsCnh9xwU00VpmvePhNYvQUWY6gJJdxXeMLGoMDFRLLGTws6DjpYk6d%2Fl8nYiu9DCqxUBmmIbVysq5goVcazizg8SZ%2Fgw%2FKST5sES165KzjnmmMeh3tP6hVV1Ckt7cqkQ%2BfXzbKbSJqKCVvsvBlUfv55qPEbeKzV04fmtzImrleCZVMqE5K9GOKTk6SD7cFaR%2B27u6TWLNidLApddleO1dhNwbF0UkYnuJMIUYiawLZ7uwirzSI7scewo8W45VENqNnBvJYu7hmREPXlfX8LMzj8Ja5XD8JaEyfWnXJVJ6n2FiWR1mCPlVkLeCt0ssDNl2lPJP3D07b4Au9VJJaISqtC8vRVuKVzIMLPbC8%2FqU8lgRScqMXSZ9d1m%2FDtkyLNebUse7B7H4rRYrMEtKolTY1eCoV1DT5Yc%3D
TEXT
],
            'With signature and without NameID format and with NameID encryption' => [true, null, true, <<<TEXT
https://idp.example.com/login?SAMLRequest=fZJfT8IwFMXf9ylI38f%2BEmfDlkyIkQSVwPTBF1O6O2iytbO3U%2Fj2jg0CaEIfb8%2Fv3HPSWmNkVVnTtDFbuYSvBtBYg%2FbsqlIi7S5j0mhJFUOBVLIKkBpOV%2BnznPpDl9ZaGcVVSf5gtymGCNoIJXtsNo1JJWRuVMO3n%2By%2B8L3AA9tbu54dRkFks4KHNruPonCUM16EQc%2B9g8bWJCatJ7F6K8QGZhINk6adu15ku3e252deSIOIjkYfPTptmwrJTIdvjamROo7I6yHsWFWXMOSqckq1EceIi2PPhzamkJvb9da9COlTli3sxesq603SU%2B2JkthUoFegvwWHt%2BX8HAKvMzCOJOno7q1oV1AnB%2FV%2FsecHY%2BdSdgZr%2BtLmnE0XqhR8P3hUumLmdo3DROR20UkpSK73tYGcDNKyVD8TDcxATIxugCT92usliXWaXv6v5Bc%3D&RelayState=https%3A%2F%2Fapp.example.com%2Fxyzzy&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=wZ%2FqBLST0xg7n7JlzLKEXJPDZUbkrhZPBAkiD2Sj4z%2BYlk%2BfnYPSwkTVt%2Fvzx3uH9A91PCrGjw2gpOo%2FTvQXIIMoeJkcxwI0uGvkg71Tc3BEouhFSJCrVFwHiaoUUl58th7jPq2maIY0lcoyBY%2BKYqdePVY0OiPpcqKltH4PLQ1Z6CssEZhCfRhue51Hx9J%2FdE8uvVJxekWuvT17VGlY5Qv2T5HIXlMz9hFPg%2BrWu6Axxfu0tEPXFZxtG49h%2FRm5tc55YKjT4WVsCnh9xwU00VpmvePhNYvQUWY6gJJdxXeMLGoMDFRLLGTws6DjpYk6d%2Fl8nYiu9DCqxUBmmIbVysq5goVcazizg8SZ%2Fgw%2FKST5sES165KzjnmmMeh3tP6hVV1Ckt7cqkQ%2BfXzbKbSJqKCVvsvBlUfv55qPEbeKzV04fmtzImrleCZVMqE5K9GOKTk6SD7cFaR%2B27u6TWLNidLApddleO1dhNwbF0UkYnuJMIUYiawLZ7uwirzSI7scewo8W45VENqNnBvJYu7hmREPXlfX8LMzj8Ja5XD8JaEyfWnXJVJ6n2FiWR1mCPlVkLeCt0ssDNl2lPJP3D07b4Au9VJJaISqtC8vRVuKVzIMLPbC8%2FqU8lgRScqMXSZ9d1m%2FDtkyLNebUse7B7H4rRYrMEtKolTY1eCoV1DT5Yc%3D
TEXT
],
            'Without signature and with NameID format and without NameID encryption' => [false, HttpMessageInterface::NAMEID_UNSPECIFIED, false, <<<TEXT
https://idp.example.com/login?SAMLRequest=fZJRT8IwFIXf9ytI38dWNuJo2BKEGElQF0AffDGlu4MmWzt7O8V%2F79wggEb6eHu%2Bc89J64yRl0XFJrXdqSW814DW6TVnXxYKWXsZk9oopjlKZIqXgMwKtpo8LNig77PKaKuFLsgv7DrFEcFYqVWHzWcxKaXKrK7F7o2P8gENKLh041M3jILI5bkIXT6KonCYcZGHQce9gMHGJCaNJ3E6K8Qa5gotV7aZ%2BzRy%2FRuXDtY0ZEHEhsPXDp01TaXitsV31lbIPE9mVR%2F2vKwK6AtdeoXeykPE9NDztokp1fZ6vU0nQna%2FXqdu%2BrRadyaTY%2B2pVliXYFZgPqSA5%2BXiFAIvM3CBJGnp9q1YW9AkP%2Bq%2FYjoIxt657ARW7LHJOZ%2BlupDiq3enTcnt%2FzVon7YTmbl5K2W1wgqEzCVkpDcpCv05NcAtxMSaGkjSLb5ckzjH6fkPS74B&RelayState=https%3A%2F%2Fapp.example.com%2Fxyzzy
TEXT
],
            'Without signature and without NameID format and without NameID encryption' => [false, null, false, <<<TEXT
https://idp.example.com/login?SAMLRequest=fZHNTsMwEITveQqUu5M4PyJdNZEKPVCpiKoNHLgg13VbS7EdvA7q4xPiIihI3ePufKMZbTBFptoOZr076rV47wW64GaYk2o1wniswt5qMAwlgmZKIDgOm9njEtIogc4aZ7hpwz%2FYdYohCuuk0R5bzKtQSb1zpufHNzbZpzSjgtBtQkleZiVhe54TNinLvNgxvs8zz70Ii4NJFQ6eYeCtEHux0OiYdsM%2BoSVJbglNG5pDVkJRvHp0PjSVmrkRPzrXIcSx3HWRODHVtSLiRsWtOchzxNW5590QU%2BrD9XpbL0J4aJoVWT1tGm8y%2B659bzT2StiNsB%2BSi%2Bf18icEXmZgHMN6pMdfwVjQ1l%2Fq%2F2KaZtP4t2wEA7%2B7fHP9CQ%3D%3D&RelayState=https%3A%2F%2Fapp.example.com%2Fxyzzy
TEXT
],
            'Without signature and with NameID format and with NameID encryption' => [false, HttpMessageInterface::NAMEID_PERSISTENT, true, <<<TEXT
https://idp.example.com/login?SAMLRequest=fZJfT8IwFMXf9ylI38f%2BEmfDlkyIkQSVwPTBF1O6O2iytbO3U%2Fj2jg0CaEIfb8%2Fv3HPSWmNkVVnTtDFbuYSvBtBYg%2FbsqlIi7S5j0mhJFUOBVLIKkBpOV%2BnznPpDl9ZaGcVVSf5gtymGCNoIJXtsNo1JJWRuVMO3n%2By%2B8L3AA9tbu54dRkFks4KHNruPonCUM16EQc%2B9g8bWJCatJ7F6K8QGZhINk6adu15ku3e252deSIOIjkYfPTptmwrJTIdvjamROo7I6yHsWFWXMOSqckq1EceIi2PPhzamkJvb9da9COlTli3sxesq603SU%2B2JkthUoFegvwWHt%2BX8HAKvMzCOJOno7q1oV1AnB%2FV%2FsecHY%2BdSdgZr%2BtLmnE0XqhR8P3hUumLmdo3DROR20UkpSK73tYGcDNKyVD8TDcxATIxugCT92usliXWaXv6v5Bc%3D&RelayState=https%3A%2F%2Fapp.example.com%2Fxyzzy
TEXT
],
            'Without signature and without NameID format and with NameID encryption' => [false, null, true, <<<TEXT
https://idp.example.com/login?SAMLRequest=fZJfT8IwFMXf9ylI38f%2BEmfDlkyIkQSVwPTBF1O6O2iytbO3U%2Fj2jg0CaEIfb8%2Fv3HPSWmNkVVnTtDFbuYSvBtBYg%2FbsqlIi7S5j0mhJFUOBVLIKkBpOV%2BnznPpDl9ZaGcVVSf5gtymGCNoIJXtsNo1JJWRuVMO3n%2By%2B8L3AA9tbu54dRkFks4KHNruPonCUM16EQc%2B9g8bWJCatJ7F6K8QGZhINk6adu15ku3e252deSIOIjkYfPTptmwrJTIdvjamROo7I6yHsWFWXMOSqckq1EceIi2PPhzamkJvb9da9COlTli3sxesq603SU%2B2JkthUoFegvwWHt%2BX8HAKvMzCOJOno7q1oV1AnB%2FV%2FsecHY%2BdSdgZr%2BtLmnE0XqhR8P3hUumLmdo3DROR20UkpSK73tYGcDNKyVD8TDcxATIxugCT92usliXWaXv6v5Bc%3D&RelayState=https%3A%2F%2Fapp.example.com%2Fxyzzy
TEXT
]
        ];
    }

    /**
     * @dataProvider isAuthnRequestSignatureRequired_isNameIdEncryptionRequired_nameIdFormat_expected_Provider
     * @test
     * @param bool $isAuthnRequestSignatureRequired
     * @param string|null $nameIdFormat
     * @param bool $isNameIdEncryptionRequired
     * @param string $expected
     * @throws SamlFlowServiceException
     * @throws MalformedUriException
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     * @throws SamlDocumentCannotWriteTextException
     */
    public function Can_generate_login_uri(
        bool $isAuthnRequestSignatureRequired,
        ?string $nameIdFormat,
        bool $isNameIdEncryptionRequired,
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

        // saml configuration
        $keys = static::newServiceProviderCryptoKeyPairFactory()
            ->newCryptoKeyPair();
        $saml = $this->newMock(SamlConfigurationInterface::class);
        $saml->expects(static::atLeastOnce())
            ->method('getServiceProviderEntityId')
            ->willReturn('http://sp.example.com/123');
        $saml->expects(static::atLeastOnce())
            ->method('getServiceProviderAssertionConsumerServiceUri')
            ->willReturn(XUri::newFromString('https://sp.example.com/acs'));
        $saml->expects(static::atLeastOnce())
            ->method('getIdentityProviderSingleSignOnUri')
            ->willReturn(XUri::newFromString('https://idp.example.com/login'));
        $saml->expects(static::atLeastOnce())
            ->method('getServiceProviderNameIdFormat')
            ->willReturn($nameIdFormat);
        $saml->expects(static::atLeastOnce())
            ->method('isNameIdEncryptionRequired')
            ->willReturn($isNameIdEncryptionRequired);
        $saml->expects(static::atLeastOnce())
            ->method('isAuthnRequestSignatureRequired')
            ->willReturn($isAuthnRequestSignatureRequired);
        if($isAuthnRequestSignatureRequired) {
            $saml->expects(static::atLeastOnce())
                ->method('getServiceProviderPrivateKey')
                ->willReturn($keys->getPrivateKey());
            $saml->expects( static::atLeastOnce())
                ->method('getServiceProviderX509Certificate')
                ->willReturn($keys->getPublicKey());
        }

        // bootstrap service
        /** @var EventDispatcherInterface $eventDispatcher */
        /** @var ContextLoggerInterface $logger */
        /** @var UuidFactoryInterface $uuidFactory */
        /** @var SessionIndexRegistryInterface $sessionIndexRegistry */
        /** @var SamlConfigurationInterface $saml */
        $eventDispatcher = $this->newMock(EventDispatcherInterface::class);
        $logger = $this->newMock(ContextLoggerInterface::class);
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

        // act
        $loginUri = $service->getLoginUri($returnUri);

        // assert
        static::assertEquals($expected, $loginUri->toString());
        $authnRequestDocument = self::newDocumentFactory()->newMessageDocument(
            gzinflate(base64_decode($loginUri->getQueryParam(HttpMessageInterface::PARAM_SAML_REQUEST)))
        )->toFormattedDocument();
        $message = <<<XML
{$authnRequestDocument->saveXML()}
XML;
        if($isNameIdEncryptionRequired) {
            static::assertEquals(<<<XML
<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/login" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="https://sp.example.com/acs">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted" AllowCreate="true"/>
</samlp:AuthnRequest>

XML
, $message);
        } else if(!StringEx::isNullOrEmpty($nameIdFormat)) {
            static::assertEquals(<<<XML
<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/login" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="https://sp.example.com/acs">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
  <samlp:NameIDPolicy Format="{$nameIdFormat}" AllowCreate="true"/>
</samlp:AuthnRequest>

XML
, $message);
        } else {
            static::assertEquals(<<<XML
<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="mindtouch_a9f2131e-1b01-4838-afc4-a98845dacf43" Version="2.0" IssueInstant="2018-07-12T14:38:55Z" Destination="https://idp.example.com/login" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="https://sp.example.com/acs">
  <saml:Issuer>http://sp.example.com/123</saml:Issuer>
</samlp:AuthnRequest>

XML
, $message);
        }

    }
}
