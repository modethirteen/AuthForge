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
namespace modethirteen\AuthForge\ServiceProvider\Saml;

use modethirteen\Crypto\CryptoKeyInterface;
use modethirteen\Http\XUri;

interface SamlConfigurationInterface {

    /**
     * @return int
     */
    public function getAllowedClockDrift() : int;

    /**
     * @return string[]
     */
    public function getAllowedSingleLogoutStatuses() : array;

    /**
     * @return XUri
     */
    public function getDefaultReturnUri() : XUri;

    /**
     * @return string
     */
    public function getIdentityProviderEntityId() : string;

    /**
     * @return XUri|null
     */
    public function getIdentityProviderSingleLogoutUri() : ?XUri;

    /**
     * @return XUri
     */
    public function getIdentityProviderSingleSignOnUri() : XUri;

    /**
     * @return CryptoKeyInterface|null
     */
    public function getIdentityProviderX509Certificate() : ?CryptoKeyInterface;

    /**
     * @return string[]
     */
    public function getNameIdFormats() : array;

    /**
     * @return XUri
     */
    public function getRelayStateBaseUri() : XUri;

    /**
     * @return AssertionAttributeClaimInterface[]
     */
    public function getServiceProviderAssertionAttributeClaims() : array;

    /**
     * @return string
     */
    public function getServiceProviderAssertionConsumerServiceBinding() : string;

    /**
     * @return XUri
     */
    public function getServiceProviderAssertionConsumerServiceUri() : XUri;

    /**
     * @return string
     */
    public function getServiceProviderEntityId() : string;

    /**
     * @return string|null
     */
    public function getServiceProviderNameIdFormat() : ?string;

    /**
     * @return CryptoKeyInterface|null
     */
    public function getServiceProviderPrivateKey() : ?CryptoKeyInterface;

    /**
     * @return string|null
     */
    public function getServiceProviderRawX509CertificateText() : ?string;

    /**
     * @return string
     */
    public function getServiceProviderServiceName() : string;

    /**
     * @return string
     */
    public function getServiceProviderSingleLogoutServiceBinding() : string;

    /**
     * @return XUri
     */
    public function getServiceProviderSingleLogoutServiceUri() : XUri;

    /**
     * @return CryptoKeyInterface|null
     */
    public function getServiceProviderX509Certificate() : ?CryptoKeyInterface;

    /**
     * @return bool
     */
    public function isAssertionEncryptionRequired() : bool;

    /**
     * @return bool
     */
    public function isAssertionSignatureRequired() : bool;

    /**
     * @return bool
     */
    public function isAuthnRequestSignatureRequired() : bool;

    /**
     * @return bool
     */
    public function isLogoutRequestSignatureRequired() : bool;

    /**
     * @return bool
     */
    public function isLogoutResponseSignatureRequired() : bool;

    /**
     * @return bool
     */
    public function isMessageSignatureRequired() : bool;

    /**
     * @return bool
     */
    public function isMetadataSignatureRequired() : bool;

    /**
     * @return bool
     */
    public function isNameIdEncryptionRequired() : bool;

    /**
     * @return bool
     */
    public function isNameIdFormatEnforcementEnabled() : bool;

    /**
     * @return bool
     */
    public function isStrictValidationRequired() : bool;
}
