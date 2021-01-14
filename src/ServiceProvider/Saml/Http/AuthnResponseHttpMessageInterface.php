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
namespace modethirteen\AuthForge\ServiceProvider\Saml\Http;

use modethirteen\AuthForge\Common\Identity\ClaimsInterface;

interface AuthnResponseHttpMessageInterface extends HttpMessageInterface {

    /**
     * @return string|null
     */
    public function getAssertionId() : ?string;

    /**
     * @return string[]
     */
    public function getAudiences() : array;

    /**
     * @return ClaimsInterface
     */
    public function getClaims() : ClaimsInterface;

    /**
     * @return string
     */
    public function getId() : string;

    /**
     * @return string
     */
    public function getInResponseToId() : string;

    /**
     * Gets the Issuers (from Response and Assertion)
     *
     * @return string[]
     */
    public function getIssuers() : array;

    /**
     * @return string
     */
    public function getNameId() : string;

    /**
     * @return string|null
     */
    public function getNameIdFormat() : ?string;

    /**
     * @return string|null
     */
    public function getSessionIndex() : ?string;

    /**
     * Gets the SessionNotOnOrAfter from the AuthnStatement
     *
     * @return int|null - The SessionNotOnOrAfter value
     */
    public function getSessionNotOnOrAfter() : ?int;

    /**
     * @return string
     */
    public function getStatusCode() : string;

    /**
     * @return string|null
     */
    public function getStatusMessage() : ?string;
}
