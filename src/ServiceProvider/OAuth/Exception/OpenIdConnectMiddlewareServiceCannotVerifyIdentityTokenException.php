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

use Jose\Component\Core\JWKSet;
use modethirteen\AuthForge\Common\Jose\SanitizedJsonWebKeySetArray;

class OpenIdConnectMiddlewareServiceCannotVerifyIdentityTokenException extends OAuthException {

    /**
     * @param JWKSet $jwks
     */
    public function __construct(JWKSet $jwks) {
        parent::__construct('Could not verify identity token with the provided JSON web key set (JWKS)', [
            'JWKS' => (new SanitizedJsonWebKeySetArray($jwks))->toArray()
        ]);
    }
}
