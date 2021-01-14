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

use DateTimeInterface;
use DOMElement;
use DOMNode;
use DOMNodeList;
use Exception;
use modethirteen\AuthForge\Common\Exception\ServerRequestInterfaceParsedBodyException;
use modethirteen\AuthForge\Common\Http\ServerRequestEx;
use modethirteen\AuthForge\Common\Identity\ClaimsInterface;
use modethirteen\AuthForge\Common\Utility\DateTimeImmutableEx;
use modethirteen\AuthForge\ServiceProvider\Saml\AssertionAttributeClaims;
use modethirteen\AuthForge\ServiceProvider\Saml\Document;
use modethirteen\AuthForge\ServiceProvider\Saml\DocumentFactoryInterface;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentSchemaValidationException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentSignatureValidationException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageAuthnResponseAssertionDoesNotContainNameIdException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageAuthnResponseDoesNotContainStatusCodeException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageAuthnResponseEncryptedAssertionException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageCannotParseHttpMessageException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionAlgorithmMismatchException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionCannotLocateKeyInfoException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionUnknownKeySizeException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageValidationException;
use modethirteen\AuthForge\ServiceProvider\Saml\SamlConfigurationInterface;
use modethirteen\Http\Exception\MalformedUriException;
use modethirteen\TypeEx\Exception\InvalidDictionaryValueException;
use modethirteen\TypeEx\StringEx;

abstract class AbstractAuthnResponseHttpMessage extends AbstractHttpMessage implements AuthnResponseHttpMessageInterface {

    /**
     * @var DateTimeInterface
     */
    protected $dateTime;

    /**
     * @var Document|null
     */
    protected $decryptedDocument = null;

    /**
     * @var array|null
     */
    private $nameIdData = null;

    /**
     * @var array|null
     */
    private $statusData = null;

    /**
     * {@inheritDoc}
     * @throws SamlHttpMessageAuthnResponseEncryptedAssertionException
     * @throws SamlHttpMessageCannotParseHttpMessageException
     */
    public function __construct(
        SamlConfigurationInterface $saml,
        ServerRequestEx $request,
        DocumentFactoryInterface $documentFactory,
        DateTimeInterface $dateTime
    ) {
        parent::__construct($saml, $request, $documentFactory);
        $this->dateTime = $dateTime;

        // quick check for the presence of EncryptedAssertion
        $encryptedAssertionNodes = $this->document->getElementsByTagName('EncryptedAssertion');
        if($encryptedAssertionNodes->length !== 0) {
            $key = $this->saml->getServiceProviderPrivateKey();
            if($key === null) {
                throw new SamlHttpMessageAuthnResponseEncryptedAssertionException();
            }
            $this->decryptedDocument = $documentFactory->newDecryptedDocument($this->document, $key);
        }
    }

    public function getAssertionId() : ?string {
        try {
            $domNodeList = $this->queryAssertion('/@ID');
        } catch(Exception $e) {
            return null;
        }
        return (($domNodeList instanceof DOMNodeList) && $domNodeList->length > 0) ? $domNodeList->item(0)->textContent : null;
    }

    public function getAudiences() : array {
        $audiences = [];
        $entries = $this->queryAssertion('/saml:Conditions/saml:AudienceRestriction/saml:Audience');
        foreach($entries as $entry) {
            $value = trim($entry->textContent);
            if(!StringEx::isNullOrEmpty($value)) {
                $audiences[] = $value;
            }
        }
        return array_unique($audiences);
    }

    /**
     * {@inheritDoc}
     * @return ClaimsInterface
     * @throws InvalidDictionaryValueException
     * @throws SamlCannotLoadCryptoKeyException
     * @throws SamlHttpMessageAuthnResponseAssertionDoesNotContainNameIdException
     * @throws SamlHttpMessageElementDecryptionAlgorithmMismatchException
     * @throws SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement
     * @throws SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException
     * @throws SamlHttpMessageElementDecryptionCannotLocateKeyInfoException
     * @throws SamlHttpMessageElementDecryptionException
     * @throws SamlHttpMessageElementDecryptionUnknownKeySizeException
     */
    public function getClaims() : ClaimsInterface {
        $claims = new AssertionAttributeClaims();
        $entries = $this->queryAssertion('/saml:AttributeStatement/saml:Attribute');
        foreach($entries as $entry) {

            /** @var DOMNode $entry */
            $name = $entry->attributes->getNamedItem('Name')->nodeValue;
            $values = [];
            foreach($entry->childNodes as $childNode) {
                $prefix = !StringEx::isNullOrEmpty($childNode->prefix) ? $childNode->prefix . ':' : '';
                if($childNode->nodeType === XML_ELEMENT_NODE && $childNode->tagName === $prefix . 'AttributeValue') {
                    $values[] = $childNode->nodeValue;
                }
            }
            $claims->set($name, $values);
        }
        return $claims->withNameId($this->getNameId());
    }

    public function getId() : string {
        return $this->document->documentElement->getAttribute('ID');
    }

    public function getInResponseToId() : string {
        return $this->document->documentElement->getAttribute('InResponseTo');
    }

    public function getIssuers() : array {
        $issuers = [];
        $responseIssuer = $this->document->query('/samlp:Response/saml:Issuer');
        if($responseIssuer->length === 1) {
            $issuers[] = $responseIssuer->item(0)->textContent;
        }
        $assertionIssuer = $this->queryAssertion('/saml:Issuer');
        if($assertionIssuer->length === 1) {
            $issuers[] = $assertionIssuer->item(0)->textContent;
        }
        return array_unique($issuers);
    }

    /**
     * {@inheritDoc}
     * @return string
     * @throws SamlCannotLoadCryptoKeyException
     * @throws SamlHttpMessageAuthnResponseAssertionDoesNotContainNameIdException
     * @throws SamlHttpMessageElementDecryptionAlgorithmMismatchException
     * @throws SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement
     * @throws SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException
     * @throws SamlHttpMessageElementDecryptionCannotLocateKeyInfoException
     * @throws SamlHttpMessageElementDecryptionException
     * @throws SamlHttpMessageElementDecryptionUnknownKeySizeException
     */
    public function getNameId() : string {
        return $this->getNameIdData()['Value'];
    }

    /**
     * {@inheritDoc}
     * @return string|null
     * @throws SamlCannotLoadCryptoKeyException
     * @throws SamlHttpMessageAuthnResponseAssertionDoesNotContainNameIdException
     * @throws SamlHttpMessageElementDecryptionAlgorithmMismatchException
     * @throws SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement
     * @throws SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException
     * @throws SamlHttpMessageElementDecryptionCannotLocateKeyInfoException
     * @throws SamlHttpMessageElementDecryptionException
     * @throws SamlHttpMessageElementDecryptionUnknownKeySizeException
     */
    public function getNameIdFormat() : ?string {
        $nameIdData = $this->getNameIdData();
        return isset($nameIdData['Format']) ? $nameIdData['Format'] : null;
    }

    public function getSessionIndex() : ?string {
        $sessionIndex = null;
        $entries = $this->queryAssertion('/saml:AuthnStatement[@SessionIndex]');
        if($entries->length !== 0) {
            $element = $entries->item(0);
            $sessionIndex = $element instanceof DOMElement ? $element->getAttribute('SessionIndex') : null;
        }
        return $sessionIndex;
    }

    public function getSessionNotOnOrAfter() : ?int {
        $notOnOrAfter = null;
        $entries = $this->queryAssertion('/saml:AuthnStatement[@SessionNotOnOrAfter]');
        if($entries->length !== 0) {
            $element = $entries->item(0);
            $notOnOrAfter = null;
            if($element instanceof DOMElement) {
                $dateTime = DateTimeImmutableEx::fromISO8601($element->getAttribute('SessionNotOnOrAfter'));
                if($dateTime instanceof DateTimeInterface) {
                    $notOnOrAfter = $dateTime->getTimestamp();
                }
            }
        }
        return $notOnOrAfter;
    }

    /**
     * {@inheritDoc}
     * @throws SamlHttpMessageAuthnResponseDoesNotContainStatusCodeException
     */
    public function getStatusCode() : string {
        return $this->getStatusData()['StatusCode'];
    }

    /**
     * {@inheritDoc}
     * @throws SamlHttpMessageAuthnResponseDoesNotContainStatusCodeException
     */
    public function getStatusMessage() : ?string {
        $data = $this->getStatusData();
        return isset($data['StatusMessage']) ? $data['StatusMessage'] : null;
    }

    /**
     * {@inheritDoc}
     * @param string|null $requestId
     * @throws MalformedUriException
     * @throws SamlCannotLoadCryptoKeyException
     * @throws SamlDocumentSchemaValidationException
     * @throws SamlDocumentSignatureValidationException
     * @throws SamlHttpMessageAuthnResponseDoesNotContainStatusCodeException
     * @throws SamlHttpMessageValidationException
     * @throws ServerRequestInterfaceParsedBodyException
     */
    public function validate(string $requestId = null) : void {
        $version = $this->document->documentElement->getAttribute('Version');
        if($version !== '2.0') {
            throw new SamlHttpMessageValidationException('AuthnResponse/@Version is not 2.0', [
                'Version' => $version
            ]);
        }
        if(!$this->document->documentElement->hasAttribute('ID')) {
            throw new SamlHttpMessageValidationException('AuthnResponse/@ID is required');
        }
        $statusCode = $this->getStatusCode();
        if($statusCode !== HttpMessageInterface::STATUS_SUCCESS) {
            throw new SamlHttpMessageValidationException('AuthnResponse/Status/StatusCode is not ' . HttpMessageInterface::STATUS_SUCCESS, [
                'StatusCode' => $statusCode,
                'StatusMessage' => $this->getStatusMessage()
            ]);
        }
        $encryptedAssertionNodes = $this->document->getElementsByTagName('EncryptedAssertion');
        $assertionNodes = $this->document->getElementsByTagName('Assertion');
        if($assertionNodes->length + $encryptedAssertionNodes->length !== 1) {
            throw new SamlHttpMessageValidationException('AuthnResponse must contain one (1) Assertion only');
        }
        $this->validateSignature();
        if($this->saml->isStrictValidationRequired()) {
            $this->document->validateSchema();

            // check if the InResponseTo matches the ID of the AuthnRequest (optional)
            $responseInResponseTo = $this->getInResponseToId() ? $this->getInResponseToId() : null;
            if($requestId !== null && $responseInResponseTo !== null && $requestId !== $responseInResponseTo) {
                throw new SamlHttpMessageValidationException('AuthnResponse/@InResponseTo does not match AuthnRequest/@ID', [
                    'InResponseTo' => $responseInResponseTo,
                    'AuthnRequestId' => $requestId
                ]);
            }

            // check encryption (optional)
            if(!$this->isDocumentEncrypted() && $this->saml->isAssertionEncryptionRequired()) {
                throw new SamlHttpMessageValidationException('AuthnResponse/Assertion is not encrypted');
            }
            if($this->saml->isNameIdEncryptionRequired()) {
                $encryptedIdNodes = $this->queryAssertion('/saml:Subject/saml:EncryptedID/xenc:EncryptedData');
                if($encryptedIdNodes->length === 0) {
                    throw new SamlHttpMessageValidationException('AuthnResponse/Assertion/Subject/@NameID is not encrypted');
                }
            }

            // check assertion timestamps (required)
            $timestampNodes = $this->document->getElementsByTagName('Conditions');
            for($i = 0; $i < $timestampNodes->length; $i++) {
                $notOnOrAfterAttribute = $timestampNodes->item($i)->attributes->getNamedItem('NotOnOrAfter');
                if($notOnOrAfterAttribute && !$this->isValidNotOnOrAfter($notOnOrAfterAttribute->textContent, $this->dateTime->getTimestamp())) {
                    throw new SamlHttpMessageValidationException("System timestamp with allowed {$this->saml->getAllowedClockDrift()}ms clock drift is on or after AuthnResponse//Conditions/@NotOnOrAfter value", [
                        'NotOnOrAfter' => $notOnOrAfterAttribute->textContent,
                        'Timestamp' => DateTimeImmutableEx::fromDateTime($this->dateTime)->toISO8601()
                    ]);
                }
                $notBeforeAttribute = $timestampNodes->item($i)->attributes->getNamedItem('NotBefore');
                if($notBeforeAttribute && !$this->isValidNotBefore($notBeforeAttribute->textContent, $this->dateTime->getTimestamp())) {
                    throw new SamlHttpMessageValidationException("System timestamp with allowed {$this->saml->getAllowedClockDrift()}ms clock drift is before AuthnResponse//Conditions/@NotBefore value", [
                        'NotBefore' => $notBeforeAttribute->textContent,
                        'Timestamp' => DateTimeImmutableEx::fromDateTime($this->dateTime)->toISO8601()
                    ]);
                }
            }

            // EncryptedAttributes are not supported
            $encryptedAttributeNodes = $this->queryAssertion('/saml:AttributeStatement/saml:EncryptedAttribute');
            if($encryptedAttributeNodes->length > 0) {
                throw new SamlHttpMessageValidationException('AuthnResponse/Assertion/AttributeStatement/EncryptedAttribute is not supported');
            }

            // check destination (optional, only base href + path is matched)
            $currentHref = self::getCurrentDestinationHref($this->request);
            if($this->document->documentElement->hasAttribute('Destination')) {
                $destination = $this->document->documentElement->getAttribute('Destination');
                if(!StringEx::isNullOrEmpty($destination)) {
                    if(strpos(rtrim($destination, '/'), rtrim($currentHref, '/')) === false) {
                        throw new SamlHttpMessageValidationException('AuthnResponse/@Destination does not match the current request URL', [
                            'Destination' => $destination,
                            'RequestUrl' => $currentHref
                        ]);
                    }
                }
            }

            // check audience (required)
            $serviceProviderEntityId = $this->saml->getServiceProviderEntityId();
            $validAudiences = $this->getAudiences();
            if(!empty($validAudiences) && !in_array($serviceProviderEntityId, $validAudiences)) {
                throw new SamlHttpMessageValidationException('AuthnResponse/Assertion/Conditions/AudienceRestriction/Audience does not contain this service provider\'s entity id', [
                    'Audiences' => $validAudiences,
                    'ServiceProviderEntityId' => $serviceProviderEntityId
                ]);
            }

            // check the issuers (required)
            $identityProviderEntityId = $this->saml->getIdentityProviderEntityId();
            $issuers = $this->getIssuers();
            foreach($issuers as $issuer) {
                if(StringEx::isNullOrEmpty($issuer) || $issuer !== $identityProviderEntityId) {
                    throw new SamlHttpMessageValidationException('AuthnResponse/Issuer or AuthnResponse/Assertion/Issuer contains an unknown identity provider id', [
                        'Issuers' => $issuers,
                        'IdentityProviderEntityId' => $identityProviderEntityId
                    ]);
                }
            }

            // check the session expiration (optional)
            $sessionNotOnOrAfter = $this->getSessionNotOnOrAfter();
            if($sessionNotOnOrAfter !== null && $sessionNotOnOrAfter + $this->saml->getAllowedClockDrift() <= $this->dateTime->getTimestamp()) {
                throw new SamlHttpMessageValidationException("System timestamp with allowed {$this->saml->getAllowedClockDrift()}ms clock drift is on or after AuthnResponse Response/Assertion/AuthnStatement/@SessionNotOnOrAfter", [
                    'SessionNotOnOrAfter' => StringEx::stringify($sessionNotOnOrAfter),
                    'Timestamp' =>  DateTimeImmutableEx::fromDateTime($this->dateTime)->toISO8601()
                ]);
            }

            // check the SubjectConfirmation, at least one SubjectConfirmation must be valid
            $anySubjectConfirmation = false;
            $subjectConfirmationNodes = $this->queryAssertion('/saml:Subject/saml:SubjectConfirmation');
            foreach($subjectConfirmationNodes as $scn) {
                if($scn->hasAttribute('Method') && $scn->getAttribute('Method') !== HttpMessageInterface::CM_BEARER) {
                    continue;
                }
                $subjectConfirmationDataNodes = $scn->getElementsByTagName('SubjectConfirmationData');
                if($subjectConfirmationDataNodes->length !== 0) {
                    $scnData = $subjectConfirmationDataNodes->item(0);
                    if($scnData->hasAttribute('InResponseTo')) {
                        $inResponseTo = $scnData->getAttribute('InResponseTo');
                        if($responseInResponseTo !== $inResponseTo) {
                            continue;
                        }
                    }
                    if($scnData->hasAttribute('Recipient')) {
                        $recipient = $scnData->getAttribute('Recipient');
                        if(!empty($recipient) && strpos(rtrim($recipient, '/'), rtrim($currentHref, '/')) === false) {
                            continue;
                        }
                    }
                    if($scnData->hasAttribute('NotOnOrAfter')) {
                        if(!$this->isValidNotOnOrAfter($scnData->getAttribute('NotOnOrAfter'), $this->dateTime->getTimestamp())) {
                            continue;
                        }
                    }
                    if($scnData->hasAttribute('NotBefore')) {
                        if(!$this->isValidNotBefore($scnData->getAttribute('NotBefore'), $this->dateTime->getTimestamp())) {
                            continue;
                        }
                    }
                    $anySubjectConfirmation = true;
                    break;
                }
            }
            if(!$anySubjectConfirmation) {
                throw new SamlHttpMessageValidationException('AuthnResponse/Assertion does not contain a valid SubjectConfirmation');
            }
        }
    }

    /**
     * @return bool
     */
    protected function isDocumentEncrypted() : bool {
        return $this->decryptedDocument !== null;
    }

    /**
     * @throws SamlCannotLoadCryptoKeyException
     * @throws SamlDocumentSignatureValidationException
     * @throws SamlHttpMessageValidationException
     * @throws ServerRequestInterfaceParsedBodyException
     * @throws MalformedUriException
     */
    abstract protected function validateSignature() : void;

    /**
     * @return array - Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
     * @throws SamlCannotLoadCryptoKeyException
     * @throws SamlHttpMessageAuthnResponseAssertionDoesNotContainNameIdException
     * @throws SamlHttpMessageElementDecryptionException
     * @throws SamlHttpMessageElementDecryptionAlgorithmMismatchException
     * @throws SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement
     * @throws SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException
     * @throws SamlHttpMessageElementDecryptionCannotLocateKeyInfoException
     * @throws SamlHttpMessageElementDecryptionUnknownKeySizeException
     */
    private function getNameIdData() : array {
        if($this->nameIdData === null) {
            $nameIdElement = null;
            $encryptedIdDataEntries = $this->queryAssertion('/saml:Subject/saml:EncryptedID/xenc:EncryptedData');
            if($encryptedIdDataEntries->length === 1) {
                $encryptedIdDataElement = $encryptedIdDataEntries->item(0);
                if($encryptedIdDataElement instanceof DOMElement) {
                    $nameIdElement = $this->getDecryptedElement($encryptedIdDataElement);
                }
            } else {
                $entries = $this->queryAssertion('/saml:Subject/saml:NameID');
                if($entries->length === 1) {
                    $nameIdElement = $entries->item(0);
                }
            }
            if($nameIdElement === null || !($nameIdElement instanceof DOMElement)) {
                throw new SamlHttpMessageAuthnResponseAssertionDoesNotContainNameIdException();
            }
            $nameIdData = [];
            $nameIdData['Value'] = $nameIdElement->nodeValue;
            foreach(['Format', 'SPNameQualifier', 'NameQualifier'] as $attr) {
                if($nameIdElement->hasAttribute($attr)) {
                    $nameIdData[$attr] = $nameIdElement->getAttribute($attr);
                }
            }
            $this->nameIdData = $nameIdData;
        }
        return $this->nameIdData;
    }

    /**
     * @return array $status - the status, an array with the code and a message
     * @throws SamlHttpMessageAuthnResponseDoesNotContainStatusCodeException
     */
    private function getStatusData() : array {
        if($this->statusData === null) {
            $statusData = [];
            $statusEntry = $this->document->query('/samlp:Response/samlp:Status');
            if($statusEntry->length === 0) {
                throw new SamlHttpMessageAuthnResponseDoesNotContainStatusCodeException();
            }
            $statusElement = $statusEntry->item(0);
            if(!($statusElement instanceof DOMElement)) {
                throw new SamlHttpMessageAuthnResponseDoesNotContainStatusCodeException();
            }
            $codeEntries = $this->document->query('/samlp:Response/samlp:Status/samlp:StatusCode', $statusElement);
            if($codeEntries->length === 0) {
                throw new SamlHttpMessageAuthnResponseDoesNotContainStatusCodeException();
            }
            $codeEntryElement = $codeEntries->item(0);
            if(!($codeEntryElement instanceof DOMElement)) {
                throw new SamlHttpMessageAuthnResponseDoesNotContainStatusCodeException();
            }
            $code = $codeEntryElement->getAttribute('Value');
            $statusData['StatusCode'] = $code;
            $messageEntries = $this->document->query('/samlp:Response/samlp:Status/samlp:StatusMessage', $statusElement);
            if($messageEntries->length !== 0) {
                $statusData['StatusMessage'] = $messageEntries->item(0)->textContent;
            }
            $this->statusData = $statusData;
        }
        return $this->statusData;
    }

    /**
     * @param string $notBefore
     * @param int $timestamp
     * @return bool
     */
    private function isValidNotBefore(string $notBefore, int $timestamp) : bool {
        $dateTime = DateTimeImmutableEx::fromISO8601($notBefore);
        if(!($dateTime instanceof DateTimeInterface)) {
            return false;
        }
        return !($dateTime->getTimestamp() > $timestamp + $this->saml->getAllowedClockDrift());
    }

    /**
     * @param string $notOnOrAfter
     * @param int $timestamp
     * @return bool
     */
    private function isValidNotOnOrAfter(string $notOnOrAfter, int $timestamp) : bool {
        $dateTime = DateTimeImmutableEx::fromISO8601($notOnOrAfter);
        if(!($dateTime instanceof DateTimeInterface)) {
            return false;
        }
        return !($dateTime->getTimestamp() + $this->saml->getAllowedClockDrift() <= $timestamp);
    }

    /**
     * Extracts node list from the assertion document
     *
     * @param string $query - xpath expresion
     * @return DOMNodeList The queried node
     */
    private function queryAssertion(string $query) : DOMNodeList {
        $document = $this->isDocumentEncrypted() ? $this->decryptedDocument : $this->document;
        $assertionNode = $this->isDocumentEncrypted()
            ? '/samlp:Response/saml:EncryptedAssertion/saml:Assertion'
            : '/samlp:Response/saml:Assertion';
        $signatureQuery = $assertionNode . '/ds:Signature/ds:SignedInfo/ds:Reference';
        $assertionReferenceNodeList = $document->query($signatureQuery);
        if($assertionReferenceNodeList->length === 0) {

            // is the response signed as a whole?
            $assertionReferenceNodeList = $document->query('/samlp:Response/ds:Signature/ds:SignedInfo/ds:Reference');
            if($assertionReferenceNodeList->length !== 0) {
                $assertionReferenceNode = $assertionReferenceNodeList->item(0);
                $id = substr($assertionReferenceNode->attributes->getNamedItem('URI')->nodeValue, 1);
                $nameQuery = "/samlp:Response[@ID='{$id}']/" . ($this->isDocumentEncrypted() ? 'saml:EncryptedAssertion/' : '') . 'saml:Assertion' . $query;
            } else {
                $nameQuery = '/samlp:Response/' . ($this->isDocumentEncrypted() ? 'saml:EncryptedAssertion/' : '') . 'saml:Assertion' . $query;
            }
        } else {
            $assertionReferenceNode = $assertionReferenceNodeList->item(0);
            $id = substr($assertionReferenceNode->attributes->getNamedItem('URI')->nodeValue, 1);
            $nameQuery = $assertionNode . "[@ID='{$id}']" . $query;
        }
        return $document->query($nameQuery);
    }
}
