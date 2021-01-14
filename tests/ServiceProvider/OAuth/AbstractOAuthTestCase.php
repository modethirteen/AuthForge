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
namespace modethirteen\AuthForge\Tests\ServiceProvider\OAuth;

use DateTimeInterface;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use modethirteen\AuthForge\Common\Jose\JsonWebSignature;
use modethirteen\AuthForge\ServiceProvider\OAuth\JsonWebTokenClaims;
use modethirteen\AuthForge\ServiceProvider\OAuth\OAuthFlowService;
use modethirteen\AuthForge\Tests\AbstractTestCase;
use modethirteen\TypeEx\Exception\InvalidDictionaryValueException;
use Ramsey\Uuid\UuidFactoryInterface;

abstract class AbstractOAuthTestCase extends AbstractTestCase {

    /**
     * @param string $audience
     * @param string $clientId
     * @param string $clientSecret
     * @param DateTimeInterface $dateTime
     * @param UuidFactoryInterface $uuidFactory
     * @return JsonWebSignature
     * @throws InvalidDictionaryValueException
     */
    protected static function getTokenAuthenticationClientAssertionSignature(
        string $audience,
        string $clientId,
        string $clientSecret,
        DateTimeInterface $dateTime,
        UuidFactoryInterface $uuidFactory
    ) : JsonWebSignature {
        $algo = new HS256();
        $jwk = JWKFactory::createFromSecret($clientSecret, [
            'alg' => $algo->name(),
            'use' => 'sig'
        ]);
        $claims = new JsonWebTokenClaims();
        foreach([
            'aud' => $audience,
            'exp' => $dateTime->getTimestamp() + 60,
            'iat' => $dateTime->getTimestamp(),
            'iss' => $clientId,
            'jti' => $uuidFactory->uuid4()->toString(),
            'sub' => $clientId
        ] as $claim => $value) {
            $claims->set($claim, $value);
        }
        return new JsonWebSignature($claims, $jwk, $algo);
    }

    /**
     * @return array<string, object> - <algo name, { algo, key }>
     */
    protected static function getSignatureKeyObjects() : array {
        $keys = [];

        // rsa
        foreach([
            new RS256(),
            new RS384(),
            new RS512(),
            new PS256(),
            new PS384(),
            new PS512()
        ] as $algo) {

            /** @var SignatureAlgorithm $algo */
            $name = $algo->name();
            $key = JWKFactory::createRSAKey(4096, [
                'alg' => $name,
                'use' => 'sig'
            ]);
            $keys[$name] = (object)[
                'algo' => $algo,
                'key' => $key
            ];
        }

        // ecdsa
        foreach([

            // TODO (modethirteen, 20190408): figure out why ECDSA intermittently fails to sign
            /*
            [new ES256(), 'P-256'],
            [new ES384(), 'P-384'],
            [new ES512(), 'P-521']
            */
        ] as $data) {

            /** @var SignatureAlgorithm $algo */
            $algo = $data[0];

            /** @var string $curve */
            $curve = $data[1];
            $key = JWKFactory::createECKey($curve);
            $keys[$algo->name()] = (object)[
                'algo' => $algo,
                'key' => $key
            ];
        }
        return $keys;
    }

    /**
     * @return string[]
     */
    protected static function getTokenClientAuthenticationMethods() : array {
        return [
            OAuthFlowService::TOKEN_AUTH_METHOD_CLIENT_SECRET_BASIC,
            OAuthFLowService::TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT,
            OAuthFlowService::TOKEN_AUTH_METHOD_CLIENT_SECRET_POST
        ];
    }
}
