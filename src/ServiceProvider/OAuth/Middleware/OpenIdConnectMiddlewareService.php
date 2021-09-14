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
namespace modethirteen\AuthForge\ServiceProvider\OAuth\Middleware;

use DateTimeInterface;
use Exception;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use modethirteen\AuthForge\Common\Http\Headers;
use modethirteen\AuthForge\Common\Identity\ClaimsInterface;
use modethirteen\AuthForge\Common\Jose\ExpirationTimeChecker;
use modethirteen\AuthForge\Common\Jose\IssuedAtChecker;
use modethirteen\AuthForge\Common\Jose\IssuerChecker;
use modethirteen\AuthForge\Common\Jose\NotBeforeChecker;
use modethirteen\AuthForge\Common\Logger\ContextLoggerInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\Exception\OpenIdConnectMiddlewareServiceCannotProcessClaimsException;
use modethirteen\AuthForge\ServiceProvider\OAuth\Exception\OpenIdConnectMiddlewareServiceCannotLoadJsonWebKeySetException;
use modethirteen\AuthForge\ServiceProvider\OAuth\Exception\OpenIdConnectMiddlewareServiceCannotVerifyIdentityTokenException;
use modethirteen\AuthForge\ServiceProvider\OAuth\JsonWebKeySetCachingInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\JsonWebTokenClaims;
use modethirteen\AuthForge\ServiceProvider\OAuth\JsonWebTokenClaimsFactory;
use modethirteen\AuthForge\ServiceProvider\OAuth\OAuthConfigurationInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\OAuthFlowService;
use modethirteen\Http\Exception\PlugUriHostRequiredException;
use modethirteen\Http\Exception\ResultParserContentExceedsMaxContentLengthException;
use modethirteen\Http\Parser\JsonParser;
use modethirteen\Http\Plug;
use modethirteen\Http\Result;
use modethirteen\Http\XUri;
use modethirteen\TypeEx\StringEx;
use modethirteen\XArray\MutableXArray;

class OpenIdConnectMiddlewareService implements OAuthMiddlewareServiceInterface {

    #region reserved oidc params
    const PARAM_ID_TOKEN_HINT = 'id_token_hint';
    const PARAM_POST_LOGOUT_REDIRECT_URI = 'post_logout_redirect_uri';
    #endregion

    #region scopes
    const SCOPE_OPENID = 'openid';
    #endregion

    /**
     * asymmetric signature verification algorithms
     *
     * @return SignatureAlgorithm[]
     */
    private static function getSupportedAlgorithms() : array {
        return [
            new RS256(),
            new RS384(),
            new RS512(),
            new ES256(),
            new ES384(),
            new ES512(),
            new PS256(),
            new PS384(),
            new PS512()
        ];
    }

    /**
     * @var OAuthConfigurationInterface
     */
    private OAuthConfigurationInterface $oauth;

    /**
     * @var JsonWebKeySetCachingInterface
     */
    private JsonWebKeySetCachingInterface $jsonWebKeySetCaching;

    /**
     * @var ContextLoggerInterface
     */
    private ContextLoggerInterface $logger;

    /**
     * @var OpenIdConnectConfigurationInterface
     */
    private OpenIdConnectConfigurationInterface $oidc;

    /**
     * @var DateTimeInterface
     */
    private DateTimeInterface $dateTime;

    public function __construct(
        OAuthConfigurationInterface $oauth,
        OpenIdConnectConfigurationInterface $oidc,
        DateTimeInterface $dateTime,
        JsonWebKeySetCachingInterface $jsonWebKeySetCaching,
        ContextLoggerInterface $logger
    ) {
        $this->oauth = $oauth;
        $this->oidc = $oidc;
        $this->dateTime = $dateTime;
        $this->jsonWebKeySetCaching = $jsonWebKeySetCaching;
        $this->logger = $logger;
    }

    /**
     * {@inheritDoc}
     * @throws ResultParserContentExceedsMaxContentLengthException
     * @throws OpenIdConnectMiddlewareServiceCannotProcessClaimsException
     * @throws OpenIdConnectMiddlewareServiceCannotVerifyIdentityTokenException
     * @throws OpenIdConnectMiddlewareServiceCannotLoadJsonWebKeySetException
     * @throws PlugUriHostRequiredException
     */
    public function getClaims(Result $tokenResult) : ClaimsInterface {
        $this->logger->debug('Processing OIDC id and access tokens...');
        $issuer = $this->oidc->getIdentityProviderIssuer();
        $clientId = $this->oauth->getRelyingPartyClientId();
        $accessToken = $tokenResult->getString('body/access_token');
        $identityToken = $tokenResult->getString('body/id_token');

        // load jwks
        $this->logger->debug('Loading JSON web key set (JWKS)...');
        $jwks = null;
        $keysUri = $this->oidc->getIdentityProviderJsonWebKeySetUri();
        if($keysUri !== null) {
            $jwks = $this->getRemoteJsonWebKeySet($keysUri, $clientId);
        }
        if($jwks === null) {

            // build jwks from configuration
            $this->logger->debug('Fetching JSON web key set (JWKS) from configuration...');
            $jwksText = $this->oidc->getIdentityProviderJsonWebKeySet();
            if(!StringEx::isNullOrEmpty($jwksText)) {
                try {
                    $jwks = JWKSet::createFromJson($jwksText);
                } catch(Exception $e) {
                    $this->logger->warning('JSON web key set (JWKS) data is invalid', [
                        'Data' => $jwksText
                    ]);
                }
            }
        }
        if($jwks === null) {
            throw new OpenIdConnectMiddlewareServiceCannotLoadJsonWebKeySetException();
        }

        // verify id token signature
        $this->logger->debug('Verifying id token...');
        $algos = self::getSupportedAlgorithms();
        $loader = new JWSLoader(

            // deserializers
            new JWSSerializerManager([new CompactSerializer()]),

            // algo verifier
            new JWSVerifier(new AlgorithmManager($algos)),

            // header checker: check for supported algos and JWS support
            new HeaderCheckerManager([
                new AlgorithmChecker(array_map(function(SignatureAlgorithm $algo) : string {
                    return $algo->name();
                }, $algos)),
            ], [
                new JWSTokenSupport()
            ])
        );

        /** @var JWS $jws */
        $jws = null;
        $signature = 0;
        $exception = null;
        try {
            $jws = $loader->loadAndVerifyWithKeySet($identityToken, $jwks, $signature);
        } catch(Exception $e) {
            $exception = new OpenIdConnectMiddlewareServiceCannotVerifyIdentityTokenException($jwks);
        }
        if($exception !== null) {
            if($keysUri !== null) {
                $this->logger->warning('Verification failed, invalidating cached JSON web key set (JWKS)...');

                // try one more time with remote source, and force a cache invalidation
                $jwks = $this->getRemoteJsonWebKeySet($keysUri, $clientId, true);
                if($jwks === null) {
                    throw new OpenIdConnectMiddlewareServiceCannotLoadJsonWebKeySetException();
                }
                try {
                    $jws = $loader->loadAndVerifyWithKeySet($identityToken, $jwks, $signature);
                } catch(Exception $e) {
                    throw new OpenIdConnectMiddlewareServiceCannotVerifyIdentityTokenException($jwks);
                }
            } else {
                throw $exception;
            }
        }

        // check claims
        $this->logger->debug('Checking claims...');

        /** @var array $claims */
        $claims = JsonConverter::decode($jws->getPayload());
        if(isset($claims[JsonWebTokenClaims::CLAIM_JTI])) {
            $this->logger->addContextHandler(function(MutableXArray $context) use ($claims) : void {
                $context->setVal('IdentityTokenId', StringEx::stringify($claims[JsonWebTokenClaims::CLAIM_JTI]));
            });
        }
        $claimCheckManager = new ClaimCheckerManager([
            new IssuedAtChecker($this->dateTime, $this->oauth->getAllowedClockDrift()),
            new NotBeforeChecker($this->dateTime, $this->oauth->getAllowedClockDrift()),
            new ExpirationTimeChecker($this->dateTime),
            new AudienceChecker($clientId),
            new IssuerChecker($issuer)
        ]);
        try {
            $claimCheckManager->check($claims, [
                JsonWebTokenClaims::CLAIM_AUD,
                JsonWebTokenClaims::CLAIM_EXP,
                JsonWebTokenClaims::CLAIM_ISS,
                JsonWebTokenClaims::CLAIM_SUB
            ]);
        } catch(InvalidClaimException $e) {
            throw OpenIdConnectMiddlewareServiceCannotProcessClaimsException::newFromInvalidClaimException($e);
        } catch(Exception $e) {
            throw OpenIdConnectMiddlewareServiceCannotProcessClaimsException::newFromException($e);
        }

        // warn if iat/nbf is not present
        $missingRecommendedClaims = [];
        foreach([JsonWebTokenClaims::CLAIM_IAT, JsonWebTokenClaims::CLAIM_NBF] as $claim) {
            if(!array_key_exists($claim, $claims)) {
                $missingRecommendedClaims[] = $claim;
            }
        }
        if(!empty($missingRecommendedClaims)) {
            $this->logger->warning('Recommended claims are missing', [
                'MissingRecommendedClaims' => $missingRecommendedClaims
            ]);
        }

        // determine missing claims
        $allowedClaims = array_merge(JsonWebTokenClaims::getRegisteredClaims(), $this->oidc->getAllowedClaims());
        $missingClaims = array_diff($allowedClaims, array_keys($claims));

        // user info lookup
        if(!empty($missingClaims)) {
            if($this->oidc->getIdentityProviderUserInfoUri() !== null) {
                $this->logger->debug('Fetching missing claims from UserInfo endpoint...');
                $userInfoResult = $this->newPlug($this->oidc->getIdentityProviderUserInfoUri())
                    ->withResultParser(new JsonParser())
                    ->withHeader(Headers::HEADER_AUTHORIZATION, "Bearer {$accessToken}")
                    ->get();
                if($userInfoResult->isSuccess()) {

                    // fill in missing claims
                    foreach($userInfoResult->getVal('body', []) as $name => $value) {
                        if(!isset($claims[$name])) {
                            $claims[$name] = $value;
                        }
                    }
                } else {
                    $this->logger->warning('UserInfo endpoint response is unsuccessful', [
                        'Body' => $userInfoResult->getBody()->toArray(),
                        'Headers' => $userInfoResult->getHeaders()->toFlattenedArray(),
                        'StatusCode' => $userInfoResult->getStatus()
                    ]);
                }
            } else {
                $this->logger->warning('There are missing claims but no configured UserInfo endpoint');
            }
        }
        return (new JsonWebTokenClaimsFactory($this->logger, $allowedClaims))->newClaims($claims);
    }

    /**
     * {@inheritDoc}
     * @param string $id - identity token provided during authentication
     */
    public function getLogoutUri(string $id, XUri $returnUri) : ?XUri {
        $uri = $this->oidc->getIdentityProviderLogoutUri();
        if($uri === null) {
            return null;
        }
        return $uri->withoutQueryParams([
            self::PARAM_ID_TOKEN_HINT,
            self::PARAM_POST_LOGOUT_REDIRECT_URI
        ])
        ->with(self::PARAM_ID_TOKEN_HINT, $id)
        ->with(self::PARAM_POST_LOGOUT_REDIRECT_URI, $returnUri->toString());
    }

    public function getScopes() : array {
        return [self::SCOPE_OPENID];
    }

    /**
     * @param XUri $keysUri - remote JWKS lookup service URL
     * @param string $clientId - OAuth client ID
     * @param bool $ignoreCachedResult - use a remote connection, ignoring the cache
     * @return JWKSet|null
     */
    private function getRemoteJsonWebKeySet(XUri $keysUri, string $clientId, bool $ignoreCachedResult = false) : ?JWKSet {
        $jwks = null;
        $keysUri = $keysUri->with(OAuthFlowService::PARAM_CLIENT_ID, $clientId);
        $this->logger->debug('Fetching JSON web key set (JWKS) from cached keys endpoint response...', [
            'Url' => $keysUri->toString()
        ]);
        $keysResult = $this->jsonWebKeySetCaching
            ->getJsonWebKeySetResult($keysUri, $ignoreCachedResult, function() use ($keysUri, $ignoreCachedResult) : Result {
                $cacheStatus = $ignoreCachedResult ? 'ignored' : 'empty';
                $this->logger->debug("Cache is {$cacheStatus}, fetching JSON web key set (JWKS) from keys endpoint...", [
                    'Url' => $keysUri->toString()
                ]);
                return $this->newPlug($keysUri)
                    ->withResultParser(new JsonParser())
                    ->get();
            });
        if($keysResult->isSuccess()) {
            $this->logger->debug('JSON web key set (JWKS) keys endpoint response is successful', [
                'Body' => $keysResult->getBody()->toArray(),
                'Headers' => $keysResult->getHeaders()->toFlattenedArray(),
                'StatusCode' => $keysResult->getStatus()
            ]);

            /** @var JWK[] $keys */
            $keys = [];
            $index = 1;
            foreach($keysResult->getBody()->getVal('keys') as $data) {
                try {
                    $this->logger->debug("Parsing JSON web key (JWK) data item #{$index}...", [
                        'Data' => $data
                    ]);
                    $keys[] = new JWK($data);
                } catch(Exception $e) {
                    $this->logger->warning("JSON web key (JWK) data item #{$index} is invalid", [
                        'Data' => $data,
                        'Error' => $e->getMessage()
                    ]);
                }
                $index++;
            }
            if(!empty($keys)) {
                $jwks = new JWKSet($keys);
                if($jwks !== null) {
                    $count = count($keys);
                    $this->logger->debug("Created JSON web key set (JWKS) from {$count} JSON web key(s) (JWK)", [
                        'JsonWebKeySet' => $jwks->jsonSerialize()
                    ]);
                }
            }
        } else {
            $this->logger->warning('JSON web key set (JWKS) keys endpoint response is unsuccessful', [
                'Body' => $keysResult->getBody()->toArray(),
                'Headers' => $keysResult->getHeaders()->toFlattenedArray(),
                'StatusCode' => $keysResult->getStatus()
            ]);
        }
        if($jwks === null) {
            $this->logger->warning('JSON web key set (JWKS) could not be created from keys endpoint');
        }
        return $jwks;
    }

    /**
     * @param XUri $uri
     * @return Plug
     * @throws PlugUriHostRequiredException
     */
    private function newPlug(XUri $uri) : Plug {
        return (new Plug($uri))->withTimeout(OAuthFlowService::PLUG_TIMEOUT);
    }
}
