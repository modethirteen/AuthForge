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

use modethirteen\Http\XUri;

interface OAuthConfigurationInterface {

    /**
     * @return int
     */
    public function getAllowedClockDrift() : int;

    /**
     * @return XUri
     */
    public function getAuthorizationCodeConsumerUri() : XUri;

    /**
     * @return XUri
     */
    public function getDefaultReturnUri() : XUri;

    /**
     * @return string
     */
    public function getRelyingPartyClientId() : string;

    /**
     * @return string
     */
    public function getRelyingPartyClientSecret() : string;

    /**
     * @return XUri
     */
    public function getIdentityProviderAuthorizationUri() : XUri;

    /**
     * @return string
     */
    public function getIdentityProviderTokenClientAuthenticationMethod() : string;

    /**
     * @return XUri
     */
    public function getIdentityProviderTokenUri() : XUri;

    /**
     * @return string[]
     */
    public function getScopes() : array;
}
