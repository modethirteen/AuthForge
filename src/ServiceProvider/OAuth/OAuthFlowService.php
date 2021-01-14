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
namespace modethirteen\AuthForge\ServiceProvider\OAuth;

use DateTimeInterface;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use modethirteen\AuthForge\Common\Http\ServerRequestEx;
use modethirteen\AuthForge\Common\Jose\JsonWebSignature;
use modethirteen\AuthForge\Common\Logger\ContextLoggerInterface;
use modethirteen\AuthForge\ServiceProvider\AuthFlowServiceInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\Event\OAuthFlowEvent;
use modethirteen\AuthForge\ServiceProvider\OAuth\Exception\OAuthFlowServiceException;
use modethirteen\AuthForge\ServiceProvider\OAuth\Middleware\OAuthMiddlewareServiceInterface;
use modethirteen\Http\Content\UrlEncodedFormDataContent;
use modethirteen\Http\Exception\PlugUriHostRequiredException;
use modethirteen\Http\Exception\ResultParserContentExceedsMaxContentLengthException;
use modethirteen\Http\Parser\JsonParser;
use modethirteen\Http\Plug;
use modethirteen\Http\XUri;
use modethirteen\TypeEx\Exception\InvalidDictionaryValueException;
use modethirteen\TypeEx\StringEx;
use modethirteen\XArray\MutableXArray;
use Psr\EventDispatcher\EventDispatcherInterface;
use Ramsey\Uuid\UuidFactoryInterface;

class OAuthFlowService implements AuthFlowServiceInterface {

    #region reserved oauth params
    const PARAM_CLIENT_ASSERTION = 'client_assertion';
    const PARAM_CLIENT_ASSERTION_TYPE = 'client_assertion_type';
    const PARAM_CLIENT_ID = 'client_id';
    const PARAM_CLIENT_SECRET = 'client_secret';
    const PARAM_CODE = 'code';
    const PARAM_ERROR = 'error';
    const PARAM_ERROR_DESCRIPTION = 'error_description';
    const PARAM_GRANT_TYPE = 'grant_type';
    const PARAM_REDIRECT_URI = 'redirect_uri';
    const PARAM_RESPONSE_TYPE = 'response_type';
    const PARAM_SCOPE = 'scope';
    const PARAM_STATE = 'state';
    #endregion

    #region session state
    const SESSION_OAUTH_HREF = 'OAuth/href';
    const SESSION_OAUTH_STATE = 'OAuth/state';
    #endregion

    #region token auth
    const TOKEN_AUTH_METHOD_CLIENT_SECRET_BASIC = 'client_secret_basic';
    const TOKEN_AUTH_METHOD_CLIENT_SECRET_POST = 'client_secret_post';
    const TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT = 'client_secret_jwt';
    #endregion

    const PLUG_TIMEOUT = 30;

    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    /**
     * @var ContextLoggerInterface
     */
    private $logger;

    /**
     * @var OAuthMiddlewareServiceInterface
     */
    private $middlewareService;

    /**
     * @var OAuthConfigurationInterface
     */
    private $oauth;

    /**
     * @var MutableXArray
     */
    private $sessionStorage;

    /**
     * @var DateTimeInterface
     */
    private $dateTime;

    /**
     * @var UuidFactoryInterface
     */
    private $uuidFactory;

    public function __construct(
        OAuthConfigurationInterface $oauth,
        DateTimeInterface $dateTime,
        ContextLoggerInterface $logger,
        OAuthMiddlewareServiceInterface $middlewareService,
        EventDispatcherInterface $eventDispatcher,
        UuidFactoryInterface $uuidFactory,
        MutableXArray $sessionStorage
    ) {
        $this->oauth = $oauth;
        $this->eventDispatcher = $eventDispatcher;
        $this->logger = $logger;
        $this->middlewareService = $middlewareService;
        $this->dateTime = $dateTime;
        $this->uuidFactory = $uuidFactory;
        $this->sessionStorage = $sessionStorage;
    }

    /**
     * {@inheritDoc}
     * @throws OAuthFlowServiceException
     */
    public function getAuthenticatedUri(ServerRequestEx $request) : XUri {
        $this->logger->debug('Processing authorization code response...');

        // OAuth 2.0 authorization code flow incorporates HTTP GET requests only, therefore it is safe to assume all parameters are query parameters
        $params = $request->getQueryParams();

        // fetch return href
        $returnHref = StringEx::stringify($this->sessionStorage->getVal(self::SESSION_OAUTH_HREF));
        $this->sessionStorage->setVal(self::SESSION_OAUTH_HREF);

        // check session state
        $state = $params->get(self::PARAM_STATE);
        $sessionState = $this->sessionStorage->getVal(self::SESSION_OAUTH_STATE);
        $this->sessionStorage->setVal(self::SESSION_OAUTH_STATE);
        if($sessionState === null) {
            $this->logger->debug('Authorization code response state not found, this may be an unsolicited authorization code...');
        } else if($sessionState !== $state) {
            throw new OAuthFlowServiceException('Provided authorization code response state did not match expected value', [
                'ExpectedState' => $sessionState,
                'ProvidedState' => $state
            ]);
        }
        $this->logger->addContextHandler(function(MutableXArray $context) use ($state) : void {
            $context->setVal('State', $state !== null ? $state : 'none');
        });
        $code = StringEx::stringify($params->get(self::PARAM_CODE));
        if(StringEx::isNullOrEmpty($code) && $params->get(self::PARAM_ERROR) !== null) {
            throw new OAuthFlowServiceException('The authorization endpoint returned an unsuccessful response', [
                'ErrorType' => $params->get(self::PARAM_ERROR),
                'ErrorDescription' => $params->get(self::PARAM_ERROR_DESCRIPTION)
            ]);
        }

        // request token
        $this->logger->debug('Requesting token(s)...');
        $tokenFormDataParameterValuePairs = [
            self::PARAM_CODE => $code,
            self::PARAM_GRANT_TYPE => 'authorization_code',
            self::PARAM_REDIRECT_URI => $this->oauth->getAuthorizationCodeConsumerUri()->toString()
        ];
        $tokenUri = $this->oauth->getIdentityProviderTokenUri();
        $clientId = $this->oauth->getRelyingPartyClientId();
        $clientSecret = $this->oauth->getRelyingPartyClientSecret();
        try {
            switch($this->oauth->getIdentityProviderTokenClientAuthenticationMethod()) {
                case self::TOKEN_AUTH_METHOD_CLIENT_SECRET_POST:
                    $tokenResult = $this->newPlug($tokenUri)
                        ->withResultParser(new JsonParser())
                        ->post(new UrlEncodedFormDataContent(array_merge([
                            self::PARAM_CLIENT_ID => $clientId,
                            self::PARAM_CLIENT_SECRET => $clientSecret
                        ], $tokenFormDataParameterValuePairs)));
                    break;
                case self::TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT:
                    $tokenResult = $this->newPlug($tokenUri)
                        ->withResultParser(new JsonParser())
                        ->post(new UrlEncodedFormDataContent(array_merge([
                            self::PARAM_CLIENT_ASSERTION => $this->getOAuthClientAssertion($clientId, $clientSecret),
                            self::PARAM_CLIENT_ASSERTION_TYPE => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                        ], $tokenFormDataParameterValuePairs)));
                    break;
                case self::TOKEN_AUTH_METHOD_CLIENT_SECRET_BASIC:
                default:
                    $tokenResult = $this->newPlug($tokenUri)
                        ->withCredentials($clientId, $clientSecret)
                        ->withResultParser(new JsonParser())
                        ->post(new UrlEncodedFormDataContent($tokenFormDataParameterValuePairs));
                    break;
            }
        } catch(
            InvalidDictionaryValueException |
            PlugUriHostRequiredException |
            ResultParserContentExceedsMaxContentLengthException $e
        ) {
            throw (new OAuthFlowServiceException('Could not build token endpoint request: {{Error}}', [
                'Error' => $e->getMessage()
            ]))->withInnerException($e);
        }
        if(!$tokenResult->isSuccess()) {
            throw new OAuthFlowServiceException('The token endpoint returned an unsuccessful response', [
                'Body' => $tokenResult->getBody()->toArray(),
                'Headers' => $tokenResult->getHeaders()->toFlattenedArray(),
                'StatusCode' => $tokenResult->getStatus()
            ]);
        }
        $claims = $this->middlewareService->getClaims($tokenResult);
        $username = $claims->getUsername();
        if(StringEx::isNullOrEmpty($username)) {
            $this->logger->warning('Could not find username in claims');
        } else {
            $this->logger->debug('Found username in claims', [
                'Username' => $claims->getUsername()
            ]);
        }

        // dispatch event to authenticate user in downstream system
        $this->eventDispatcher->dispatch(new OAuthFlowEvent($this->dateTime, $tokenResult, $claims, $this->middlewareService));

        // follow return uri
        $returnUri = XUri::tryParse($returnHref);
        return $returnUri !== null ? $returnUri : $this->oauth->getDefaultReturnUri();
    }

    public function getLoginUri(XUri $returnUri) : XUri {
        $clientId = $this->oauth->getRelyingPartyClientId();
        $state = $this->uuidFactory->uuid4()->toString();
        $uri = $this->oauth->getIdentityProviderAuthorizationUri()
            ->withoutQueryParams([
                self::PARAM_CLIENT_ID,
                self::PARAM_REDIRECT_URI,
                self::PARAM_RESPONSE_TYPE,
                self::PARAM_STATE,
                self::PARAM_SCOPE
            ])
            ->with(self::PARAM_CLIENT_ID, $clientId)
            ->with(self::PARAM_REDIRECT_URI, $this->oauth->getAuthorizationCodeConsumerUri()->toString())
            ->with(self::PARAM_RESPONSE_TYPE, 'code')
            ->with(self::PARAM_STATE, $state);

        // scope
        $scopes = array_unique(array_merge($this->middlewareService->getScopes(), $this->oauth->getScopes()));
        $uri = $uri->with(self::PARAM_SCOPE, implode(' ', $scopes));

        // store session state
        $returnHref = $returnUri->toString();
        $this->sessionStorage->setVal(self::SESSION_OAUTH_HREF, $returnHref);
        $this->sessionStorage->setVal(self::SESSION_OAUTH_STATE, $state);
        $this->logger->debug('Generating authorization code request', [
            'AuthorizeEndpointUrl' => $uri->toString(),
            'ClientId' => $clientId,
            'ReturnUrl' => $returnHref,
            'Scopes' => $scopes,
            'State' => $state
        ]);
        return $uri;
    }

    public function getLogoutUri(string $id, XUri $returnUri) : ?XUri {
        return $this->middlewareService->getLogoutUri($id, $returnUri);
    }

    /**
     * @param string $clientId
     * @param string $clientSecret
     * @return string
     * @throws InvalidDictionaryValueException
     */
    private function getOAuthClientAssertion(string $clientId, string $clientSecret) : string {
        $algo = new HS256();
        $jwk = JWKFactory::createFromSecret($clientSecret, [
            'alg' => $algo->name(),
            'use' => 'sig'
        ]);
        $now = $this->dateTime->getTimestamp();
        $claims = new JsonWebTokenClaims();
        foreach([
            'aud' => $this->oauth->getIdentityProviderTokenUri()->toString(),
            'exp' => $now + 60,
            'iat' => $now,
            'iss' => $clientId,
            'jti' => $this->uuidFactory->uuid4()->toString(),
            'sub' => $clientId
        ] as $claim => $value) {
            $claims->set($claim, $value);
        }
        return (new JsonWebSignature($claims, $jwk, $algo))->toString();
    }

    /**
     * @param XUri $uri
     * @return Plug
     * @throws PlugUriHostRequiredException
     */
    private function newPlug(XUri $uri) : Plug {
        return (new Plug($uri))->withTimeout(self::PLUG_TIMEOUT);
    }
}
