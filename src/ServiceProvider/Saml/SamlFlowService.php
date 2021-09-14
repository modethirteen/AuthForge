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
use modethirteen\AuthForge\Common\Exception\ServerRequestInterfaceParsedBodyException;
use modethirteen\AuthForge\Common\Http\ServerRequestEx;
use modethirteen\AuthForge\Common\Logger\ContextLoggerInterface;
use modethirteen\AuthForge\Common\Utility\ArrayEx;
use modethirteen\AuthForge\ServiceProvider\AuthFlowServiceInterface;
use modethirteen\AuthForge\ServiceProvider\Saml\Event\SamlAuthnResponseFlowEvent;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotDeflateOutgoingHttpMessageException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotEncryptMessageDataNameIdException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotGenerateSignatureException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentSchemaValidationException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentSignatureValidationException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlFlowServiceException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageAuthnResponseAssertionDoesNotContainNameIdException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageAuthnResponseEncryptedAssertionException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageCannotParseHttpMessageException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionAlgorithmMismatchException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionCannotLocateKeyInfoException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionUnknownKeySizeException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageValidationException;
use modethirteen\AuthForge\ServiceProvider\Saml\Http\PostAuthnResponseHttpMessage;
use modethirteen\AuthForge\ServiceProvider\Saml\Http\RedirectAuthnResponseHttpMessage;
use modethirteen\Http\Exception\MalformedUriException;
use modethirteen\Http\XUri;
use modethirteen\TypeEx\Exception\InvalidDictionaryValueException;
use modethirteen\TypeEx\StringEx;
use modethirteen\XArray\MutableXArray;
use Psr\EventDispatcher\EventDispatcherInterface;
use Ramsey\Uuid\UuidFactoryInterface;

class SamlFlowService implements AuthFlowServiceInterface {
    use RelayStateAuthFlowServiceTrait;

    /**
     * @var DateTimeInterface
     */
    private DateTimeInterface $dateTime;

    /**
     * @var DocumentFactoryInterface
     */
    private DocumentFactoryInterface $documentFactory;

    /**
     * @var EventDispatcherInterface
     */
    private EventDispatcherInterface $eventDispatcher;

    /**
     * @var ContextLoggerInterface
     */
    private ContextLoggerInterface $logger;

    /**
     * @var SamlConfigurationInterface
     */
    private SamlConfigurationInterface $saml;

    /**
     * @var SamlUriFactoryInterface
     */
    private $uriFactory;

    public function __construct(
        SamlConfigurationInterface $saml,
        DateTimeInterface $dateTime,
        ContextLoggerInterface $logger,
        UuidFactoryInterface $uuidFactory,
        EventDispatcherInterface $eventDispatcher,
        DocumentFactoryInterface $documentFactory,
        SessionIndexRegistryInterface $sessionIndexRegistry
    ) {
        $this->saml = $saml;
        $this->dateTime = $dateTime;
        $this->logger = $logger;
        $this->eventDispatcher = $eventDispatcher;
        $this->uriFactory = new SamlUriFactory($saml, $dateTime, $logger, $uuidFactory, $sessionIndexRegistry);
        $this->documentFactory = $documentFactory;
    }

    /**
     * {@inheritDoc}
     * @throws SamlFlowServiceException
     */
    public function getAuthenticatedUri(ServerRequestEx $request) : XUri {
        $this->logger->debug('Attempting to locate and parse AuthnResponse...');

        // AuthnResponse -- HTTP POST or HTTP Redirect Binding (POST is preferred and tested, Redirect is for SFDC failed assertions)
        try {
            $authnResponse = $request->isPost()
                ? new PostAuthnResponseHttpMessage($this->saml, $request, $this->documentFactory, $this->dateTime)
                : new RedirectAuthnResponseHttpMessage($this->saml, $request, $this->documentFactory, $this->dateTime);
        } catch (SamlHttpMessageAuthnResponseEncryptedAssertionException | SamlHttpMessageCannotParseHttpMessageException $e) {
            throw (new SamlFlowServiceException('Could not parse AuthnResponse from HTTP request: {{Error}}', [
                'Error' => $e->getMessage()
            ]))->withInnerException($e);
        }

        // upgrade to AuthnResponse logger
        $this->logger->addContextHandler(function (MutableXArray $context) use ($authnResponse): void {
            $id = $authnResponse->getId();
            $context->setVal('DocumentId', $id);
            $context->setVal('ResponseId', $id);
            $context->setVal('AssertionId', StringEx::stringify($authnResponse->getAssertionId()));
            $context->setVal('InResponseToId', $authnResponse->getInResponseToId());
        });
        $this->logger->debug('AuthnResponse parsed, attempting to validate...');

        // validate AuthnResponse
        try {
            $authnResponse->validate();
        } catch(SamlDocumentSchemaValidationException $e) {
            throw (new SamlFlowServiceException('AuthnResponse schema is invalid: {{Error}}', [
                'Error' => $e->getMessage(),
                'ValidationErrors' => $e->getErrors()
            ]))->withInnerException($e);
        } catch(SamlHttpMessageValidationException $e) {
            throw (new SamlFlowServiceException('AuthnResponse is invalid: {{Error}}', ArrayEx::merge([
                'Error' => $e->getMessage()
            ], $e->getContext())))->withInnerException($e);
        } catch(
            MalformedUriException |
            ServerRequestInterfaceParsedBodyException |
            SamlCannotLoadCryptoKeyException |
            SamlDocumentSignatureValidationException $e
        ) {
            throw (new SamlFlowServiceException('AuthnResponse is invalid: {{Error}}', [
                'Error' => $e->getMessage()
            ]))->withInnerException($e);
        }
        $this->logger->debug('AuthnResponse is valid, attempting to authenticate...');

        // locate NameId and authenticate the user
        try {
            $username = $authnResponse->getNameId();
            $format = $authnResponse->getNameIdFormat();
        } catch(
            SamlCannotLoadCryptoKeyException |
            SamlHttpMessageAuthnResponseAssertionDoesNotContainNameIdException |
            SamlHttpMessageElementDecryptionAlgorithmMismatchException |
            SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement |
            SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException |
            SamlHttpMessageElementDecryptionCannotLocateKeyInfoException |
            SamlHttpMessageElementDecryptionException |
            SamlHttpMessageElementDecryptionUnknownKeySizeException $e
        ) {
            throw (new SamlFlowServiceException('Could not get NameID from AuthnResponse'))
                ->withInnerException($e);
        }
        $formats = $this->saml->getNameIdFormats();
        if($this->saml->isNameIdFormatEnforcementEnabled() && !in_array($format, $formats)) {
            throw new SamlFlowServiceException('Could not find valid NameID format in AuthnResponse', [
                'NameIdFormat' => $format === null ? '' : $format,
                'AllowedNameIdFormats' => $formats
            ]);
        }
        $this->logger->debug('Found NameID in AuthnResponse', [
            'NameId' => $username,
            'NameIdFormat' => $format
        ]);
        try {
            $claims = $authnResponse->getClaims();
        } catch(
            InvalidDictionaryValueException |
            SamlCannotLoadCryptoKeyException |
            SamlHttpMessageAuthnResponseAssertionDoesNotContainNameIdException |
            SamlHttpMessageElementDecryptionAlgorithmMismatchException |
            SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement |
            SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException |
            SamlHttpMessageElementDecryptionCannotLocateKeyInfoException |
            SamlHttpMessageElementDecryptionException |
            SamlHttpMessageElementDecryptionUnknownKeySizeException $e
        ) {
            throw (new SamlFlowServiceException('Could not get assertion attribute claims from AuthnResponse: {{Error}}', [
                'Error' => $e->getMessage()
            ]))->withInnerException($e);
        }

        // dispatch event to authenticate user in downstream system
        $this->eventDispatcher->dispatch(
            new SamlAuthnResponseFlowEvent($this->dateTime, $claims, StringEx::stringify($authnResponse->getSessionIndex()))
        );
        return $this->getRedirectUriFromRequestRelayState($this->saml, $request, $this->logger);
    }

    /**
     * {@inheritDoc}
     * @throws SamlFlowServiceException
     */
    public function getLoginUri(XUri $returnUri) : XUri {
        try {
            return $this->uriFactory->newAuthnRequestUri($returnUri);
        } catch(
            SamlCannotDeflateOutgoingHttpMessageException |
            SamlCannotGenerateSignatureException |
            SamlCannotLoadCryptoKeyException $e
        ) {
            throw (new SamlFlowServiceException('AuthnRequest is invalid: {{Error}}', [
                'Error' => $e->getMessage()
            ]))->withInnerException($e);
        }
    }

    /**
     * {@inheritDoc}
     * @throws SamlFlowServiceException
     */
    public function getLogoutUri(string $id, XUri $returnUri) : ?XUri {
        try {
            return $this->uriFactory->newLogoutRequestUri($id, $returnUri);
        } catch(
            SamlCannotDeflateOutgoingHttpMessageException |
            SamlCannotEncryptMessageDataNameIdException |
            SamlCannotGenerateSignatureException |
            SamlCannotLoadCryptoKeyException $e
        ) {
            throw (new SamlFlowServiceException('LogoutRequest is invalid: {{Error}}', [
                'Error' => $e->getMessage()
            ]))->withInnerException($e);
        }
    }
}
