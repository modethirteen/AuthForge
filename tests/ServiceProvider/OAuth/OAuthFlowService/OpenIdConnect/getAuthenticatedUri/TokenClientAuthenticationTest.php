<?php
/** @noinspection DuplicatedCode */
declare(strict_types=1);
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
namespace modethirteen\AuthForge\Tests\ServiceProvider\OAuth\OAuthFlowService\OpenIdConnect\getAuthenticatedUri;

use DateTimeImmutable;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use modethirteen\AuthForge\Common\Exception\NotSupportedException;
use modethirteen\AuthForge\Common\Http\Headers;
use modethirteen\AuthForge\Common\Http\ServerRequestEx;
use modethirteen\AuthForge\Common\Jose\JsonWebSignature;
use modethirteen\AuthForge\Common\Logger\ContextLoggerInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\Event\OAuthFlowEvent;
use modethirteen\AuthForge\ServiceProvider\OAuth\Exception\OAuthFlowServiceException;
use modethirteen\AuthForge\ServiceProvider\OAuth\JsonWebKeySetCaching;
use modethirteen\AuthForge\ServiceProvider\OAuth\JsonWebTokenClaims;
use modethirteen\AuthForge\ServiceProvider\OAuth\Middleware\OpenIdConnectConfigurationInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\Middleware\OpenIdConnectMiddlewareService;
use modethirteen\AuthForge\ServiceProvider\OAuth\OAuthConfigurationInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\OAuthFlowService;
use modethirteen\AuthForge\Tests\ServiceProvider\OAuth\AbstractOAuthTestCase;
use modethirteen\Http\Content\ContentType;
use modethirteen\Http\Content\JsonContent;
use modethirteen\Http\Content\UrlEncodedFormDataContent;
use modethirteen\Http\Exception\JsonContentCannotSerializeArrayException;
use modethirteen\Http\Exception\MalformedUriException;
use modethirteen\Http\Mock\MockPlug;
use modethirteen\Http\Mock\MockRequestMatcher;
use modethirteen\Http\Plug;
use modethirteen\Http\QueryParams;
use modethirteen\Http\Result;
use modethirteen\Http\XUri;
use modethirteen\TypeEx\Exception\InvalidDictionaryValueException;
use modethirteen\XArray\JsonArray;
use modethirteen\XArray\MutableXArray;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\SimpleCache\CacheInterface;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidFactoryInterface;

class TokenClientAuthenticationTest extends AbstractOAuthTestCase {

    /**
     * @return array
     */
    public static function tokenClientAuthenticationMethod_Provider() : array {
        $params = [];
        foreach(self::getTokenClientAuthenticationMethods() as $method) {
            $params[$method] = [$method];
        }
        return $params;
    }

    /**
     * @dataProvider tokenClientAuthenticationMethod_Provider
     * @test
     * @param string $tokenClientAuthenticationMethod
     * @throws InvalidDictionaryValueException
     * @throws JsonContentCannotSerializeArrayException
     * @throws MalformedUriException
     * @throws NotSupportedException
     * @throws OAuthFlowServiceException
     */
    public function Can_process_token_and_dispatch_event_and_return_redirect_uri(
        string $tokenClientAuthenticationMethod
    ) : void {

        // request
        $code = Uuid::uuid4()->toString();
        $state = Uuid::uuid4()->toString();
        $request = $this->newMock(ServerRequestEx::class);
        $request->expects(static::atLeastOnce())
            ->method('getQueryParams')
            ->willReturn(QueryParams::newFromArray([
                'code' => $code,
                'state' => $state
            ]));
        $dateTime = new DateTimeImmutable('2018-07-12T14:38:55.529Z');
        $sessionStorage = [];
        $x = new MutableXArray($sessionStorage);
        $x->setVal(OAuthFlowService::SESSION_OAUTH_STATE, $state);
        $x->setVal(OAuthFlowService::SESSION_OAUTH_HREF, 'https://app.example.com/dashboard');

        // token signature key
        $algo = new RS256();
        $key = JWKFactory::createRSAKey(4096, [
            'alg' => $algo->name(),
            'use' => 'sig'
        ]);

        // event dispatcher
        /** @var OAuthFlowEvent[] $events */
        $events = [];
        $eventDispatcher = $this->newMock(EventDispatcherInterface::class);
        $eventDispatcher->expects(static::atLeastOnce())
            ->method('dispatch')
            ->willReturnCallback(function(object $event) use (&$events) {
                $events[] = $event;
            });

        // uuid generation for client assertion token grant type
        $uuidFactory = $this->newMock(UuidFactoryInterface::class);
        if($tokenClientAuthenticationMethod === OAuthFlowService::TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT) {
            $uuidFactory->expects(static::atLeastOnce())
                ->method('uuid4')
                ->willReturn(Uuid::fromString('38c9c334-de3d-484b-aaeb-520b787be782'));
        }

        // cache for remote jwks
        $cache = $this->newMock(CacheInterface::class);
        $cache->expects(static::once())
            ->method('get')
            ->willReturn(null);

        /** @var CacheInterface $cache */
        $caching = new JsonWebKeySetCaching($cache, function() {
            return '12345';
        });

        // oauth configuration
        $oauth = $this->newMock(OAuthConfigurationInterface::class);
        $authorizationCodeConsumerUri = XUri::newFromString('https://app.example.com/@oidc/code');
        $oauth->expects(static::atLeastOnce())
            ->method('getAuthorizationCodeConsumerUri')
            ->willReturn($authorizationCodeConsumerUri);
        $relyingPartyClientId = '0oafuv29cxTJWpZng0h7';
        $oauth->expects(static::atLeastOnce())
            ->method('getRelyingPartyClientId')
            ->willReturn($relyingPartyClientId);
        $relyingPartyClientSecret = '5931B3995B9E7AC55499087B83E4C3DC4AD8C505';
        $oauth->expects(static::atLeastOnce())
            ->method('getRelyingPartyClientSecret')
            ->willReturn($relyingPartyClientSecret);
        $identityProviderTokenUri = XUri::newFromString('https://idp.example.com/token');
        $oauth->expects(static::atLeastOnce())
            ->method('getIdentityProviderTokenUri')
            ->willReturn($identityProviderTokenUri);
        $oauth->expects(static::atLeastOnce())
            ->method('getIdentityProviderTokenClientAuthenticationMethod')
            ->willReturn($tokenClientAuthenticationMethod);

        // openid connect configuration
        $oidc = $this->newMock(OpenIdConnectConfigurationInterface::class);
        $oidc->expects(static::atLeastOnce())
            ->method('getAllowedClaims')
            ->willReturn(['groups', 'first_name', 'last_name']);
        $issuer = 'plugh';
        $oidc->expects(static::atLeastOnce())
            ->method('getIdentityProviderIssuer')
            ->willReturn($issuer);
        $identityProviderJsonWebKeySetUri = XUri::newFromString('https://idp.example.com/keys');
        $oidc->expects(static::atLeastOnce())
            ->method('getIdentityProviderJsonWebKeySetUri')
            ->willReturn($identityProviderJsonWebKeySetUri);

        // bootstrap service
        /** @var OAuthConfigurationInterface $oauth */
        /** @var OpenIdConnectConfigurationInterface $oidc */
        /** @var EventDispatcherInterface $eventDispatcher */
        /** @var UuidFactoryInterface $uuidFactory */
        /** @var ContextLoggerInterface $logger */
        $logger = $this->newMock(ContextLoggerInterface::class);
        $middlewareService = new OpenIdConnectMiddlewareService(
            $oauth, $oidc, $dateTime, $caching, $logger
        );
        $service = new OAuthFlowService(
            $oauth, $dateTime, $logger, $middlewareService, $eventDispatcher, $uuidFactory, $x
        );

        // mock jwks request
        MockPlug::register(
            (new MockRequestMatcher(Plug::METHOD_GET,
                $identityProviderJsonWebKeySetUri->with('client_id', $relyingPartyClientId)
            )),
            (new Result())
                ->withStatus(200)
                ->withBody(
                    (new JsonArray((new JWKSet([$key->toPublic()]))->jsonSerialize()))->toJson()
                )
                ->withHeaders(Headers::newFromHeaderNameValuePairs([
                    [Headers::HEADER_CONTENT_TYPE, ContentType::JSON]
                ]))
        );

        // mock token request
        $claims = new JsonWebTokenClaims();
        foreach([
            'iat' => $dateTime->getTimestamp(),
            'nbf' => $dateTime->getTimestamp(),
            'exp' => $dateTime->getTimestamp() + 3600,
            'iss' => $issuer,
            'aud' => $relyingPartyClientId,
            'sub' => 'modethirteen',
            'first_name' => 'jack',
            'last_name' => 'fubar',
            'groups' => ['a', 'b', 'c'],
            'quuv' => 'qux',
            'fubar' => 'fff'
        ] as $claim => $value) {
            $claims->set($claim, $value);
        }
        $tokenRequestContent = [
            'code' => $code,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $authorizationCodeConsumerUri->toString()
        ];
        switch($tokenClientAuthenticationMethod) {
            case OAuthFlowService::TOKEN_AUTH_METHOD_CLIENT_SECRET_BASIC:
                $matcher = (new MockRequestMatcher(Plug::METHOD_POST, $identityProviderTokenUri))
                    ->withContent((new UrlEncodedFormDataContent($tokenRequestContent)))
                    ->withAddedHeaders(Headers::newFromHeaderNameValuePairs([
                        [Headers::HEADER_AUTHORIZATION, 'Basic ' . base64_encode("{$relyingPartyClientId}:{$relyingPartyClientSecret}")]
                    ]));
                break;
            case OAuthFlowService::TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT:
                $matcher = (new MockRequestMatcher(Plug::METHOD_POST, $identityProviderTokenUri))
                    ->withContent((new UrlEncodedFormDataContent(array_merge([
                        'client_assertion' => self::getTokenAuthenticationClientAssertionSignature(
                            $identityProviderTokenUri->toString(),
                            $relyingPartyClientId,
                            $relyingPartyClientSecret,
                            $dateTime,
                            $uuidFactory
                        )->toString(),
                        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                    ], $tokenRequestContent))));
                break;
            case OAuthFlowService::TOKEN_AUTH_METHOD_CLIENT_SECRET_POST:
                $matcher = (new MockRequestMatcher(Plug::METHOD_POST, $identityProviderTokenUri))
                    ->withContent((new UrlEncodedFormDataContent(array_merge([
                        'client_id' => '0oafuv29cxTJWpZng0h7',
                        'client_secret' => '5931B3995B9E7AC55499087B83E4C3DC4AD8C505'
                    ], $tokenRequestContent))));
                break;
            default:
                throw new NotSupportedException('Unsupported token client authentication method');
        }
        MockPlug::register($matcher,
            (new Result())
                ->withStatus(200)
                ->withContent(JsonContent::newFromArray([
                    'access_token' => 'asdf',
                    'id_token' => (new JsonWebSignature($claims, $key, $algo))->toString()
                ]))
        );

        // act
        /** @var ServerRequestEx $request */
        $result = $service->getAuthenticatedUri($request);

        // assert
        static::assertTrue(MockPlug::verifyAll());
        static::assertEquals('https://app.example.com/dashboard', $result->toString());
        static::assertCount(1, $events);
        $event = $events[0];
        static::assertEquals(1531406335, $event->getDateTime()->getTimestamp());
        static::assertEquals(OpenIdConnectMiddlewareService::class, $event->getMiddlewareServiceName());
        static::assertEquals([
            'iat' => 1531406335,
            'nbf' => 1531406335,
            'exp' => 1531409935,
            'iss' => 'plugh',
            'aud' => '0oafuv29cxTJWpZng0h7',
            'sub' => 'modethirteen',
            'first_name' => 'jack',
            'last_name' => 'fubar',
            'groups' => ['a', 'b', 'c']
        ], $event->getClaims()->toArray());
        static::assertEquals('modethirteen', $event->getClaims()->getUsername());
    }
}
