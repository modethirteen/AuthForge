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

use modethirteen\Http\XUri;

interface SamlUriFactoryInterface {

    /**
     * @param XUri $returnUri
     * @return XUri
     */
    public function newAuthnRequestUri(XUri $returnUri, bool $sha512EncryptionEnabled = false) : XUri;

    /**
     * @param string $username
     * @param XUri $returnUri
     * @return XUri|null
     */
    public function newLogoutRequestUri(string $username, XUri $returnUri) : ?XUri;

    /**
     * @param XUri $returnUri
     * @param string $inResponseTo
     * @return XUri|null
     */
    public function newLogoutResponseUri(XUri $returnUri, string $inResponseTo) : ?XUri;
}
