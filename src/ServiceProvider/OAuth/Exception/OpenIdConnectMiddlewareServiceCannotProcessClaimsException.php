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
namespace modethirteen\AuthForge\ServiceProvider\OAuth\Exception;

use Exception;
use Jose\Component\Checker\InvalidClaimException;

class OpenIdConnectMiddlewareServiceCannotProcessClaimsException extends OAuthException {

    /**
     * @param Exception $e
     * @return OpenIdConnectMiddlewareServiceCannotProcessClaimsException
     */
    public static function newFromException(Exception $e) : OpenIdConnectMiddlewareServiceCannotProcessClaimsException {
        return new self($e->getMessage(), null);
    }

    /**
     * @param InvalidClaimException $e
     * @return OpenIdConnectMiddlewareServiceCannotProcessClaimsException
     */
    public static function newFromInvalidClaimException(InvalidClaimException $e) : OpenIdConnectMiddlewareServiceCannotProcessClaimsException {
        return new self($e->getMessage(), $e->getClaim(), $e->getValue());
    }

    /**
     * @param string $message
     * @param string|null $claim
     * @param mixed|null $value
     */
    private function __construct(string $message, ?string $claim, $value = null) {
        $context = [
            'Error' => $message
        ];
        if($claim !== null) {
            $context['ClaimName'] = $claim;
        }
        if($value !== null) {
            $context['ClaimValue'] = $value;
        }
        parent::__construct('Could not process identity token claims, {{Error}}', $context);
    }
}
