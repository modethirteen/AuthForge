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
namespace modethirteen\AuthForge\ServiceProvider\OAuth\Middleware;

use modethirteen\Http\XUri;

interface OpenIdConnectConfigurationInterface {

    /**
     * @return string[]
     */
    public function getAllowedClaims() : array;

    /**
     * @return string
     */
    public function getIdentityProviderIssuer() : string;

    /**
     * @return string|null
     */
    public function getIdentityProviderJsonWebKeySet() : ?string;

    /**
     * @return XUri|null
     */
    public function getIdentityProviderJsonWebKeySetUri() : ?XUri;

    /**
     * @return XUri|null
     */
    public function getIdentityProviderLogoutUri() : ?XUri;

    /**
     * @return XUri|null
     */
    public function getIdentityProviderUserInfoUri() : ?XUri;
}
