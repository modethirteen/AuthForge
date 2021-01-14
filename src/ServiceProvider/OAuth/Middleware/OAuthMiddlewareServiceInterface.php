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

use modethirteen\AuthForge\Common\Identity\ClaimsInterface;
use modethirteen\Http\Result;
use modethirteen\Http\XUri;

interface OAuthMiddlewareServiceInterface {

    /**
     * @param Result $tokenResult - OAuth 2.0 token HTTP result
     * @return ClaimsInterface
     */
    public function getClaims(Result $tokenResult) : ClaimsInterface;

    /**
     * @param string $id
     * @param XUri $returnUri
     * @return XUri|null
     */
    public function getLogoutUri(string $id, XUri $returnUri) : ?XUri;

    /**
     * @return string[]
     */
    public function getScopes() : array;
}
