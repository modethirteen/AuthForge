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

use modethirteen\AuthForge\Common\Logger\ContextLoggerInterface;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadServiceProviderCertificate;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCertificateServiceException;
use modethirteen\Crypto\CryptoKeyInterface;

class SamlCertificateService implements SamlCertificateServiceInterface {

    /**
     * @var ContextLoggerInterface
     */
    private $logger;

    /**
     * @var SamlConfigurationInterface
     */
    private $saml;

    public function __construct(
        SamlConfigurationInterface $saml,
        ContextLoggerInterface $logger
    ) {
        $this->saml = $saml;
        $this->logger = $logger;
    }

    /**
     * {@inheritDoc}
     * @throws SamlCertificateServiceException
     */
    public function getX509Certificate() : ?CryptoKeyInterface {
        $this->logger->debug('Loading service provider x.509 certificate...');
        if($this->saml->getServiceProviderRawX509CertificateText() === null) {
            $this->logger->debug('Service provider x.509 certificate not found');
            return null;
        }
        $certificate = $this->saml->getServiceProviderX509Certificate();
        if($certificate === null) {
            $e = new SamlCannotLoadServiceProviderCertificate();
            throw (new SamlCertificateServiceException('{{Error}}', [
                'Error' => $e->getMessage()
            ]))->withInnerException($e);
        }
        return $certificate;
    }
}
