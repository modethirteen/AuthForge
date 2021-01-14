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
namespace modethirteen\AuthForge\ServiceProvider\OAuth\Event;

use DateTimeInterface;
use modethirteen\AuthForge\Common\Event\AbstractEvent;
use modethirteen\AuthForge\Common\Identity\ClaimsInterface;
use modethirteen\AuthForge\Common\Utility\ArrayEx;
use modethirteen\AuthForge\ServiceProvider\OAuth\Middleware\OAuthMiddlewareServiceInterface;
use modethirteen\Http\Result;

class OAuthFlowEvent extends AbstractEvent  {

    /**
     * @var ClaimsInterface
     */
    private $claims;

    /**
     * @var string
     */
    private $middlewareServiceName;

    /**
     * @var Result
     */
    private $tokenResult;

    /**
     * @param DateTimeInterface $dateTime
     * @param Result $tokenResult
     * @param ClaimsInterface $claims
     * @param OAuthMiddlewareServiceInterface $middlewareService
     */
    public function __construct(DateTimeInterface $dateTime, Result $tokenResult, ClaimsInterface $claims, OAuthMiddlewareServiceInterface $middlewareService) {
        parent::__construct($dateTime);
        $this->tokenResult = $tokenResult;
        $this->claims = $claims;
        $this->middlewareServiceName = get_class($middlewareService);
    }

    /**
     * @return ClaimsInterface
     */
    public function getClaims() : ClaimsInterface {
        return $this->claims;
    }

    /**
     * @return string
     */
    public function getMiddlewareServiceName() : string {
        return $this->middlewareServiceName;
    }

    /**
     * @return Result
     */
    public function getTokenResult() : Result {
        return $this->tokenResult;
    }

    /**
     * {@inheritDoc}
     */
    public function toArray() : array {
        return ArrayEx::merge([
            'Claims' => $this->claims->toArray(),
            'Username' => $this->claims->getUsername(),
            'MiddlewareServiceName' => $this->middlewareServiceName,
            'TokenResult' => $this->tokenResult->toArray()
        ], parent::toArray());
    }
}
