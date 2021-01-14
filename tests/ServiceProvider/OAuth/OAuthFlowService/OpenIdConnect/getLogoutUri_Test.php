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
namespace modethirteen\AuthForge\Tests\ServiceProvider\OAuth\OAuthFlowService\OpenIdConnect;

use DateTimeImmutable;
use modethirteen\AuthForge\Common\Logger\ContextLoggerInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\JsonWebKeySetCachingInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\Middleware\OpenIdConnectConfigurationInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\Middleware\OpenIdConnectMiddlewareService;
use modethirteen\AuthForge\ServiceProvider\OAuth\OAuthConfigurationInterface;
use modethirteen\AuthForge\ServiceProvider\OAuth\OAuthFlowService;
use modethirteen\AuthForge\Tests\ServiceProvider\OAuth\AbstractOAuthTestCase;
use modethirteen\Http\Exception\MalformedUriException;
use modethirteen\Http\XUri;
use modethirteen\XArray\MutableXArray;
use Psr\EventDispatcher\EventDispatcherInterface;
use Ramsey\Uuid\UuidFactoryInterface;

class getLogoutUri_Test extends AbstractOAuthTestCase {

    /**
     * @test
     * @throws MalformedUriException
     */
    public function Can_get_authorization_code_request_uri() : void {

        // request
        $sessionStorage = [];
        $x = new MutableXArray($sessionStorage);

        // oauth configuration
        $oauth = $this->newMock(OAuthConfigurationInterface::class);

        // openid connect configuration
        $oidc = $this->newMock(OpenIdConnectConfigurationInterface::class);
        $oidc->expects(static::any())
            ->method('getIdentityProviderLogoutUri')
            ->willReturn(XUri::newFromString('https://idp.example.com/logout'));

        // session
        $dateTime = new DateTimeImmutable('2018-07-12T14:38:55.529Z');
        $returnUri = XUri::newFromString('https://app.example.com/kb');

        // bootstrap service
        /** @var OAuthConfigurationInterface $oauth */
        /** @var OpenIdConnectConfigurationInterface $oidc */
        /** @var EventDispatcherInterface $eventDispatcher */
        /** @var JsonWebKeySetCachingInterface $caching */
        /** @var UuidFactoryInterface $uuidFactory */
        /** @var ContextLoggerInterface $logger */
        $eventDispatcher = $this->newMock(EventDispatcherInterface::class);
        $caching = $this->newMock(JsonWebKeySetCachingInterface::class);
        $uuidFactory = $this->newMock(UuidFactoryInterface::class);
        $logger = $this->newMock(ContextLoggerInterface::class);
        $middlewareService = new OpenIdConnectMiddlewareService(
            $oauth, $oidc, $dateTime, $caching, $logger
        );
        $service = new OAuthFlowService(
            $oauth, $dateTime, $logger, $middlewareService, $eventDispatcher, $uuidFactory, $x
        );

        // act
        $result = $service->getLogoutUri('xyzzy', $returnUri);

        // assert
        static::assertEquals('https://idp.example.com/logout?id_token_hint=xyzzy&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fkb', $result->toString());
    }
}
