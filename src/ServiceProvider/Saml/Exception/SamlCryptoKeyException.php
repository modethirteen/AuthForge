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

class SamlCryptoKeyException extends SamlException {

    /**
     * @var string
     */
    private string $error;

    /**
     * @var CryptoKeyInterface
     */
    private CryptoKeyInterface $key;

    /**
     * @param string $message
     * @param CryptoKeyInterface $key
     * @param string $error
     */
    public function __construct(string $message, CryptoKeyInterface $key, string $error) {
        parent::__construct($message, [
            'Error' => $error,
            'Fingerprint' => $key->getFingerprint(),
            'Format' => $key->getFormat()
        ]);
        $this->error = $error;
    }

    /**
     * @return string
     */
    public function getError() : string {
        return $this->error;
    }

    /**
     * @return CryptoKeyInterface
     */
    public function getKey() : CryptoKeyInterface {
        return $this->key;
    }
}
