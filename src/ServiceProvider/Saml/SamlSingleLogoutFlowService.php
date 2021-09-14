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
use modethirteen\AuthForge\ServiceProvider\Saml\Event\SamlSingleLogoutRequestFlowEvent;
use modethirteen\AuthForge\ServiceProvider\Saml\Event\SamlSingleLogoutResponseFlowEvent;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotDeflateOutgoingHttpMessageException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotGenerateSignatureException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentSchemaValidationException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageCannotParseHttpMessageException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionAlgorithmMismatchException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionCannotLocateKeyInfoException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionUnknownKeySizeException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageLogoutRequestDoesNotContainNameIdException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageValidationException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlSingleLogoutFlowServiceException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlSingleLogoutFlowServiceLogoutRequestException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlSingleLogoutFlowServiceLogoutResponseException;
use modethirteen\AuthForge\ServiceProvider\Saml\Http\HttpMessageInterface;
use modethirteen\AuthForge\ServiceProvider\Saml\Http\RedirectLogoutRequestHttpMessage;
use modethirteen\AuthForge\ServiceProvider\Saml\Http\RedirectLogoutResponseHttpMessage;
use modethirteen\Http\Exception\MalformedUriException;
use modethirteen\Http\XUri;
use modethirteen\TypeEx\StringEx;
use modethirteen\XArray\MutableXArray;
use Psr\EventDispatcher\EventDispatcherInterface;
use Ramsey\Uuid\UuidFactoryInterface;

class SamlSingleLogoutFlowService implements SamlSingleLogoutFlowServiceInterface {
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
     * @var SessionIndexRegistryInterface
     */
    private SessionIndexRegistryInterface $sessionIndexRegistry;

    /**
     * @var UuidFactoryInterface
     */
    private UuidFactoryInterface $uuidFactory;

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
        $this->uuidFactory = $uuidFactory;
        $this->eventDispatcher = $eventDispatcher;
        $this->documentFactory = $documentFactory;
        $this->sessionIndexRegistry = $sessionIndexRegistry;
    }

    /**
     * @param ServerRequestEx $request
     * @return XUri
     * @throws SamlSingleLogoutFlowServiceLogoutRequestException
     * @throws SamlSingleLogoutFlowServiceLogoutResponseException
     * @throws SamlSingleLogoutFlowServiceException
     */
    public function getPostLogoutRedirectUri(ServerRequestEx $request) : XUri {
        $this->logger->debug('Attempting to locate and parse LogoutResponse or LogoutRequest..');
        try {
            $isLogoutRequest = $request->getParam(HttpMessageInterface::PARAM_SAML_REQUEST) !== null;
            $isLogoutResponse = $request->getParam(HttpMessageInterface::PARAM_SAML_RESPONSE) !== null;
        } catch(ServerRequestInterfaceParsedBodyException $e) {
            throw (new SamlSingleLogoutFlowServiceException('Could not find a SAMLResponse (LogoutResponse) or SAMLRequest (LogoutRequest) in HTTP request', [
                'Error' => $e->getMessage()
            ]))->withInnerException($e);
        }

        // handle SP-initiated SLO IdP response (service provider user initiated single logout can redirect home on errors)
        if($isLogoutResponse) {
            $this->logger->debug('SAMLResponse found in HTTP request, attempting to parse LogoutResponse...');
            $logoutResponse = null;
            try {
                $logoutResponse = new RedirectLogoutResponseHttpMessage($this->saml, $request, $this->documentFactory);
            } catch(SamlHttpMessageCannotParseHttpMessageException $e) {
                throw (new SamlSingleLogoutFlowServiceLogoutResponseException('Could not parse LogoutResponse from HTTP request: {{Error}}', [
                    'Error' => $e->getMessage()
                ]))->withInnerException($e);
            }

            // upgrade to logout_response logger
            $this->logger->addContextHandler(function(MutableXArray $context) use ($logoutResponse) : void {
                $id = $logoutResponse->getId();
                $context->setVal('DocumentId', $id);
                $context->setVal('LogoutResponseId', $id);
                $context->setVal('InResponseToId', $logoutResponse->getInResponseToId());
            });
            $this->logger->debug('LogoutResponse parsed, attempting to validate...');

            // validate response
            try {
                $logoutResponse->validate();
            } catch(SamlDocumentSchemaValidationException $e) {
                throw (new SamlSingleLogoutFlowServiceLogoutResponseException('LogoutResponse schema is invalid: {{Error}}', [
                    'Error' => $e->getMessage(),
                    'ValidationErrors' => $e->getErrors()
                ]))->withInnerException($e);
            } catch(SamlHttpMessageValidationException $e) {
                throw (new SamlSingleLogoutFlowServiceLogoutResponseException('LogoutResponse is invalid: {{Error}}', ArrayEx::merge([
                    'Error' => $e->getMessage()
                ], $e->getContext())))->withInnerException($e);
            } catch(
                MalformedUriException |
                ServerRequestInterfaceParsedBodyException |
                SamlCannotLoadCryptoKeyException $e
            ) {
                throw (new SamlSingleLogoutFlowServiceLogoutResponseException('LogoutResponse is invalid: {{Error}}', [
                    'Error' => $e->getMessage()
                ]))->withInnerException($e);
            }
            $this->logger->debug('LogoutResponse is valid, attempting to logout...');

            // check if logout was successful and dispatch event for downstream logout handling
            $status = $logoutResponse->getStatus();
            if(StringEx::isNullOrEmpty($status) || !in_array($status, $this->saml->getAllowedSingleLogoutStatuses())) {
                throw new SamlSingleLogoutFlowServiceLogoutResponseException('LogoutResponse was not successful', ['Status' => $status]);
            }
            $this->eventDispatcher->dispatch(new SamlSingleLogoutResponseFlowEvent($this->dateTime, $status));
            return $this->getRedirectUriFromRequestRelayState($this->saml, $request, $this->logger);
        }

        // handle IdP-initiated SLO request (idp initiated single logout can halt on errors and provide limited details in response)
        if($isLogoutRequest) {
            $this->logger->debug('SAMLRequest found in HTTP request, attempting to parse LogoutRequest...');
            $logoutRequest = null;
            try {
                $logoutRequest = new RedirectLogoutRequestHttpMessage($this->saml, $request, $this->documentFactory);
            } catch(SamlHttpMessageCannotParseHttpMessageException $e) {
                throw (new SamlSingleLogoutFlowServiceLogoutRequestException('Could not parse LogoutRequest from HTTP request: {{Error}}', [
                    'Error' => $e->getMessage()
                ]))->withInnerException($e);
            }

            // upgrade to logout_request logger
            $this->logger->addContextHandler(function(MutableXArray $context) use ($logoutRequest) : void {
                $id = $logoutRequest->getId();
                $context->setVal('DocumentId', $id);
                $context->setVal('LogoutRequestId', $id);
            });
            $this->logger->debug('LogoutRequest parsed, attempting to validate...');

            // validate request
            try {
                $logoutRequest->validate();
            } catch(SamlDocumentSchemaValidationException $e) {
                throw (new SamlSingleLogoutFlowServiceLogoutRequestException('LogoutRequest schema is invalid: {{Error}}', [
                    'Error' => $e->getMessage(),
                    'ValidationErrors' => $e->getErrors()
                ]))->withInnerException($e);
            } catch(SamlHttpMessageValidationException $e) {
                throw (new SamlSingleLogoutFlowServiceLogoutRequestException('LogoutRequest is invalid: {{Error}}', ArrayEx::merge([
                    'Error' => $e->getMessage()
                ], $e->getContext())))->withInnerException($e);
            } catch(
                MalformedUriException |
                ServerRequestInterfaceParsedBodyException |
                SamlCannotLoadCryptoKeyException $e
            ) {
                throw (new SamlSingleLogoutFlowServiceLogoutRequestException('LogoutRequest is invalid: {{Error}}', [
                    'Error' => $e->getMessage()
                ]))->withInnerException($e);
            }
            $this->logger->debug('LogoutRequest is valid, attempting to dirty SessionIndexes...');
            try {
                $username = $logoutRequest->getNameId();
            } catch(
                SamlHttpMessageElementDecryptionAlgorithmMismatchException |
                SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement |
                SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException |
                SamlHttpMessageElementDecryptionCannotLocateKeyInfoException |
                SamlHttpMessageElementDecryptionException |
                SamlHttpMessageElementDecryptionUnknownKeySizeException |
                SamlHttpMessageLogoutRequestDoesNotContainNameIdException |
                SamlCannotLoadCryptoKeyException $e
            ) {
                throw new SamlSingleLogoutFlowServiceLogoutRequestException('Could not process LogoutRequest NameId: {{Error}}', [
                    'Error' => $e->getMessage()
                ]);
            }
            if(!StringEx::isNullOrEmpty($username)) {
                $sessionIndexes = $logoutRequest->getSessionIndexes();
                foreach($sessionIndexes as $sessionIndex) {
                    $this->logger->debug('Dirtying SessionIndex to force sign out on next action', [
                        'NameId' => $username,
                        'SessionIndex' => $sessionIndex
                    ]);
                    $this->sessionIndexRegistry->dirtySessionIndex($username, $sessionIndex);
                }
                $this->eventDispatcher->dispatch(new SamlSingleLogoutRequestFlowEvent($this->dateTime, $username, $sessionIndexes));
            }
            $this->logger->debug('SessionIndexes dirtied, attempting to redirect back to IdP SLO...');
            $redirectUri = $this->getRedirectUriFromRequestRelayState($this->saml, $request, $this->logger);
            $logoutResponseUri = null;
            try {
                $logoutResponseUri = (new SamlUriFactory($this->saml, $this->dateTime, $this->logger, $this->uuidFactory, $this->sessionIndexRegistry))
                    ->newLogoutResponseUri($redirectUri, $logoutRequest->getId());
            } catch(
                SamlCannotDeflateOutgoingHttpMessageException |
                SamlCannotGenerateSignatureException |
                SamlCannotLoadCryptoKeyException $e
            ) {
                $this->logger->warning('LogoutRequest error reported, {{Error}}', [
                    'Error' => $e->getMessage()
                ]);
            }
            if($logoutResponseUri === null) {
                $this->logger->warning('This service is not configured with a valid IdP SLO URL, redirecting to available RelayState instead...');

                // there is no IdP slo url to redirect to, so we can safely return to the RelayState that was provided
                return $redirectUri;
            }
            return $logoutResponseUri;
        }

        // it's hard to tell if this is IdP or SP initiated, but we can infer its SP initiated from the the lack of a SAMLRequest
        throw new SamlSingleLogoutFlowServiceException('Could not find a SAMLResponse or SAMLRequest in HTTP request');
    }
}
