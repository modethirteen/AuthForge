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
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use modethirteen\AuthForge\Common\Http\ServerRequestEx;
use modethirteen\AuthForge\Common\Jose\JsonWebSignature;
use modethirteen\AuthForge\Common\Logger\ContextLoggerInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\Event\OAuthFlowEvent;
use modethirteen\AuthForge\ServiceProvider\OAuth\Exception\OAuthFlowServiceException;
use modethirteen\AuthForge\ServiceProvider\OAuth\JsonWebKeySetCachingInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\JsonWebTokenClaims;
use modethirteen\AuthForge\ServiceProvider\OAuth\Middleware\OpenIdConnectConfigurationInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\Middleware\OpenIdConnectMiddlewareService;
use modethirteen\AuthForge\ServiceProvider\OAuth\OAuthConfigurationInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\OAuthFlowService;
use modethirteen\AuthForge\Tests\ServiceProvider\OAuth\AbstractOAuthTestCase;
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
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidFactoryInterface;

class LocalJsonWebKeysTest extends AbstractOAuthTestCase {

    /**
     * @return array
     */
    public static function key_algo_Provider() : array {
        $params = [];
        foreach(self::getSignatureKeyObjects() as $name => $object) {
            $params["{$name} signature key"] = [
                $object->key,
                $object->algo,
            ];
        }
        return $params;
    }

    /**
     * @dataProvider key_algo_Provider
     * @test
     * @param JWK $key
     * @param SignatureAlgorithm $algo
     * @throws InvalidDictionaryValueException
     * @throws JsonContentCannotSerializeArrayException
     * @throws MalformedUriException
     * @throws OAuthFlowServiceException
     */
    public function Can_process_token_and_dispatch_event_and_return_redirect_uri(
        JWK $key,
        SignatureAlgorithm $algo
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

        // event dispatcher
        /** @var OAuthFlowEvent[] $events */
        $events = [];
        $eventDispatcher = $this->newMock(EventDispatcherInterface::class);
        $eventDispatcher->expects(static::atLeastOnce())
            ->method('dispatch')
            ->willReturnCallback(function(object $event) use (&$events) {
                $events[] = $event;
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
             ->willReturn(OAuthFlowService::TOKEN_AUTH_METHOD_CLIENT_SECRET_POST);

        // openid connect configuration
        $oidc = $this->newMock(OpenIdConnectConfigurationInterface::class);
        $oidc->expects(static::atLeastOnce())
            ->method('getAllowedClaims')
            ->willReturn(['groups', 'first_name', 'last_name']);
        $issuer = 'plugh';
        $oidc->expects(static::atLeastOnce())
            ->method('getIdentityProviderIssuer')
            ->willReturn($issuer);
        $oidc->expects(static::atLeastOnce())
            ->method('getIdentityProviderJsonWebKeySet')
            ->willReturn((new JsonArray((new JWKSet([$key->toPublic()]))->jsonSerialize()))->toJson());

        // bootstrap service
        /** @var OAuthConfigurationInterface $oauth */
        /** @var OpenIdConnectConfigurationInterface $oidc */
        /** @var EventDispatcherInterface $eventDispatcher */
        /** @var JsonWebKeySetCachingInterface $caching */
        /** @var UuidFactoryInterface $uuidFactory */
        /** @var ContextLoggerInterface $logger */
        $logger = $this->newMock(ContextLoggerInterface::class);
        $uuidFactory = $this->newMock(UuidFactoryInterface::class);
        $caching = $this->newMock(JsonWebKeySetCachingInterface::class);
        $middlewareService = new OpenIdConnectMiddlewareService(
            $oauth, $oidc, $dateTime, $caching, $logger
        );
        $service = new OAuthFlowService(
            $oauth, $dateTime, $logger, $middlewareService, $eventDispatcher, $uuidFactory, $x
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
        MockPlug::register(
            (new MockRequestMatcher(Plug::METHOD_POST, $identityProviderTokenUri))
                ->withContent((new UrlEncodedFormDataContent(array_merge([
                    'client_id' => '0oafuv29cxTJWpZng0h7',
                    'client_secret' => '5931B3995B9E7AC55499087B83E4C3DC4AD8C505',
                    'code' => $code,
                    'grant_type' => 'authorization_code',
                    'redirect_uri' => $authorizationCodeConsumerUri->toString()
                ])))),
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
