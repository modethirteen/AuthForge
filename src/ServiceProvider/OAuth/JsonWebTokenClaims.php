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
namespace modethirteen\AuthForge\ServiceProvider\OAuth;

use modethirteen\AuthForge\Common\Identity\AbstractClaims;
use modethirteen\AuthForge\Common\Identity\ClaimsInterface;
use modethirteen\TypeEx\StringEx;
use modethirteen\XArray\Serialization\JsonSerializer;
use modethirteen\XArray\XArray;

class JsonWebTokenClaims extends AbstractClaims implements ClaimsInterface {

    #region reserved jwt claims (see https://www.iana.org/assignments/jwt/jwt.xhtml#claims for detailed list)
    const CLAIM_AUD = 'aud';
    const CLAIM_EXP = 'exp';
    const CLAIM_JTI = 'jti';
    const CLAIM_IAT = 'iat';
    const CLAIM_ISS = 'iss';
    const CLAIM_NBF = 'nbf';
    const CLAIM_SUB = 'sub';
    #endregion

    /**
     * @return string[]
     */
    public static function getRegisteredClaims() : array {
        return static::$registeredClaims;
    }

    /**
     * registered jwt claims that are used for validation only (https://tools.ietf.org/html/rfc7519#section-4.1)
     *
     * @var string[]
     */
    private static array $registeredClaims = [
        self::CLAIM_AUD,
        self::CLAIM_EXP,
        self::CLAIM_JTI,
        self::CLAIM_IAT,
        self::CLAIM_ISS,
        self::CLAIM_NBF,
        self::CLAIM_SUB
    ];

    public function getUsername() : ?string {
        $subject = $this->getClaim(self::CLAIM_SUB);
        return $subject !== null ? StringEx::stringify($subject) : null;
    }

    public function toJson() : string {
        return (new XArray($this->toArray()))
            ->withSerializer(new JsonSerializer())
            ->toString();
    }

    public function toSecureArray() : array {
        return array_filter($this->toArray(), function($claim) : bool {
            return !in_array($claim, static::getRegisteredClaims());
        }, ARRAY_FILTER_USE_KEY);
    }

    public function toSecureJson() : string {
        return (new XArray($this->toSecureArray()))
            ->withSerializer(new JsonSerializer())
            ->toString();
    }
}
