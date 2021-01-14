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
namespace modethirteen\AuthForge\ServiceProvider\Saml\Exception;

use modethirteen\Crypto\CryptoKeyInterface;

class SamlCannotEncryptMessageDataNameIdException extends SamlCryptoKeyException {

    /**
     * @param CryptoKeyInterface $certificate
     * @param string $error
     */
    public function __construct(CryptoKeyInterface $certificate, string $error) {
        parent::__construct('Failure encrypting message data NameId. Check the configured identity provider x.509 certificate, {{Error}}', $certificate, $error);
    }
}
