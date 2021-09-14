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

use DateTimeInterface;
use DOMDocument;
use DOMElement;
use modethirteen\AuthForge\Common\Logger\ContextLoggerInterface;
use modethirteen\AuthForge\Common\Utility\DateTimeImmutableEx;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotGenerateSignatureException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentCannotWriteTextException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentNoElementToSignException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentSchemaValidationException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentSignatureException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlMetadataServiceException;
use modethirteen\TypeEx\StringEx;

class SamlMetadataService implements SamlMetadataServiceInterface {
    const TIME_VALID = 172800;  // 2 days
    const TIME_CACHED = 604800; // 1 week

    /**
     * @var DateTimeInterface
     */
    private DateTimeInterface $dateTime;

    /**
     * @var DocumentFactoryInterface
     */
    private DocumentFactoryInterface $documentFactory;

    /**
     * @var ContextLoggerInterface
     */
    private ContextLoggerInterface $logger;

    /**
     * @var SamlConfigurationInterface
     */
    private SamlConfigurationInterface $saml;

    public function __construct(
        SamlConfigurationInterface $saml,
        DateTimeInterface $dateTime,
        ContextLoggerInterface $logger,
        DocumentFactoryInterface $documentFactory
    ) {
        $this->saml = $saml;
        $this->dateTime = $dateTime;
        $this->logger = $logger;
        $this->documentFactory = $documentFactory;
    }

    /**
     * {@inheritDoc}
     * @throws SamlMetadataServiceException
     */
    public function getMetadataDocument() : Document {
        $this->logger->debug('Building service provider metadata document...');

        // build default metadata
        $document = $this->documentFactory->newMetadataDocument();
        $document->formatOutput = true;
        $entityDescriptorDocument = $document->createElementNS(Document::NS_MD, 'md:EntityDescriptor');
        $entityDescriptorDocument->setAttribute('validUntil',  (new DateTimeImmutableEx())
            ->setTimestamp($this->dateTime->getTimestamp() + self::TIME_VALID)
            ->toISO8601()
        );
        $entityDescriptorDocument->setAttribute('cacheDuration', DateTimeImmutableEx::toISO8601Duration(self::TIME_CACHED));
        $entityDescriptorDocument->setAttribute('entityID', $this->saml->getServiceProviderEntityId());
        $document->appendChild($entityDescriptorDocument);

        // add service provider sso descriptor
        $serviceProviderSSODescriptorDocument = $document->createElementNS(Document::NS_MD, 'md:SPSSODescriptor');
        $serviceProviderSSODescriptorDocument->setAttribute('AuthnRequestsSigned', StringEx::stringify($this->saml->isAuthnRequestSignatureRequired()));
        $serviceProviderSSODescriptorDocument->setAttribute('WantAssertionsSigned', StringEx::stringify($this->saml->isAssertionSignatureRequired()));
        $serviceProviderSSODescriptorDocument->setAttribute('protocolSupportEnumeration', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $entityDescriptorDocument->appendChild($serviceProviderSSODescriptorDocument);

        // add single logout service -> service provider sso descriptor
        $singleLogoutService = $document->createElementNS(Document::NS_MD, 'md:SingleLogoutService');
        $singleLogoutService->setAttribute('Binding', $this->saml->getServiceProviderSingleLogoutServiceBinding());
        $singleLogoutService->setAttribute('Location', $this->saml->getServiceProviderSingleLogoutServiceUri()->toString());
        $serviceProviderSSODescriptorDocument->appendChild($singleLogoutService);

        // add nameid format -> service provider sso descriptor
        $nameIdFormat = $this->saml->getServiceProviderNameIdFormat();
        if(!StringEx::isNullOrEmpty($nameIdFormat)) {
            $nameidDocument = $document->createElementNS(Document::NS_MD, 'md:NameIDFormat', $nameIdFormat);
            $serviceProviderSSODescriptorDocument->appendChild($nameidDocument);
        }

        // add assertion consumer service -> service provider sso descriptor
        $assertionConsumerService = $document->createElementNS(Document::NS_MD, 'md:AssertionConsumerService');
        $assertionConsumerService->setAttribute('Binding', $this->saml->getServiceProviderAssertionConsumerServiceBinding());
        $assertionConsumerService->setAttribute('Location', $this->saml->getServiceProviderAssertionConsumerServiceUri()->toString());
        $assertionConsumerService->setAttribute('index', '1');
        $serviceProviderSSODescriptorDocument->appendChild($assertionConsumerService);

        // add attribute consuming service -> service provider sso descriptor
        $attributes = $this->saml->getServiceProviderAssertionAttributeClaims();
        if(!empty($attributes)) {
            $attributeConsumingServiceDocument = $document->createElementNS(Document::NS_MD, 'md:AttributeConsumingService');
            $attributeConsumingServiceDocument->setAttribute('index', '1');
            $serviceNameDocument = $document->createElementNS(Document::NS_MD, 'md:ServiceName');
            $serviceNameDocument->setAttribute('xml:lang', 'en');
            $serviceNameDocument->nodeValue = $this->saml->getServiceProviderServiceName();
            $attributeConsumingServiceDocument->appendChild($serviceNameDocument);
            foreach($attributes as $attribute) {
                $this->addAttribute($document, $attributeConsumingServiceDocument, $attribute);
            }
            $serviceProviderSSODescriptorDocument->appendChild($attributeConsumingServiceDocument);
        }

        // add public certificate and sign metadata
        $certificate = $this->saml->getServiceProviderX509Certificate();
        if($certificate !== null) {

            // add service provider certificate to metadata
            $certificateDocument = $document->createElementNS(Document::NS_DS, 'ds:X509Certificate', $certificate->toText());
            $keyDataDocument = $document->createElementNS(Document::NS_DS, 'ds:X509Data');
            $keyDataDocument->appendChild($certificateDocument);
            $keyInfoDocument = $document->createElementNS(Document::NS_DS, 'ds:KeyInfo');
            $keyInfoDocument->appendChild($keyDataDocument);
            $keyDescriptor = $document->createElementNS(Document::NS_MD, 'md:KeyDescriptor');
            $serviceProviderSSODescriptorDocument->insertBefore($keyDescriptor->cloneNode(), $serviceProviderSSODescriptorDocument->firstChild);
            $serviceProviderSSODescriptorDocument->insertBefore($keyDescriptor->cloneNode(), $serviceProviderSSODescriptorDocument->firstChild);
            $signing = $document->getElementsByTagName('KeyDescriptor')->item(0);
            if($signing instanceof DOMElement) {
                $signing->setAttribute('use', 'signing');
            }
            $encryption = $document->getElementsByTagName('KeyDescriptor')->item(1);
            if($encryption instanceof DOMElement) {
                $encryption->setAttribute('use', 'encryption');
            }
            $signing->appendChild($keyInfoDocument);
            $encryption->appendChild($keyInfoDocument->cloneNode(true));
        }

        // sign metadata
        if($this->saml->isMetadataSignatureRequired()) {
            $this->logger->debug('Signing service provider metadata document...');
            try {
                if($certificate === null) {
                    throw new SamlCannotGenerateSignatureException();
                }
                $key = $this->saml->getServiceProviderPrivateKey();
                if($key === null) {
                    throw new SamlCannotGenerateSignatureException();
                }
                $document = $document->withSignature($key, $certificate);
            } catch(
                SamlCannotLoadCryptoKeyException |
                SamlDocumentNoElementToSignException |
                SamlDocumentSignatureException |
                SamlDocumentCannotWriteTextException |
                SamlCannotGenerateSignatureException $e
            ) {
                throw (new SamlMetadataServiceException('Service provider metadata document cannot be signed: {{Error}}', [
                    'Error' => $e->getMessage()
                ]))->withInnerException($e);
            }
        }

        // validate metadata
        $this->logger->debug('Validating service provider metadata document schema...');
        try {
            $document->validateSchema();
        } catch(SamlDocumentSchemaValidationException $e) {
            throw (new SamlMetadataServiceException('Service provider metadata document schema is invalid: {{Error}}', [
                'Error' => $e->getMessage(),
                'ValidationErrors' => $e->getErrors()
            ]))->withInnerException($e);
        }
        return $document;
    }

    /**
     * @param DOMDocument $document
     * @param DOMElement $acsDocument
     * @param AssertionAttributeClaimInterface $attribute
     */
    private function addAttribute(DOMDocument $document, DOMElement $acsDocument, AssertionAttributeClaimInterface $attribute) : void {
        $requestedAttributeDocument = $document->createElementNS(Document::NS_MD, 'md:RequestedAttribute');
        $requestedAttributeDocument->setAttribute('isRequired', StringEx::stringify($attribute->isRequired()));
        $requestedAttributeDocument->setAttribute('Name', $attribute->getName());
        if(!StringEx::isNullOrEmpty($attribute->getFriendlyName())) {
            $requestedAttributeDocument->setAttribute('FriendlyName', $attribute->getFriendlyName());
        }
        if(!StringEx::isNullOrEmpty($attribute->getNameFormat())) {
            $requestedAttributeDocument->setAttribute('NameFormat', $attribute->getNameFormat());
        }
        $acsDocument->appendChild($requestedAttributeDocument);
    }
}
