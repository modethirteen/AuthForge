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

use modethirteen\AuthForge\Common\Identity\AbstractClaims;
use modethirteen\AuthForge\Common\Identity\ClaimsInterface;
use modethirteen\Http\Result;
use modethirteen\Http\XUri;
use modethirteen\XArray\Serialization\JsonSerializer;
use modethirteen\XArray\XArray;

class NoopOAuthMiddlewareService implements OAuthMiddlewareServiceInterface {

    public function getClaims(Result $tokenResult) : ClaimsInterface {
        return new class extends AbstractClaims implements ClaimsInterface {

            public function getUsername(): ?string {
                return null;
            }

            public function toJson() : string {
                return (new XArray($this->toArray()))
                    ->withSerializer(new JsonSerializer())
                    ->toString();
            }

            public function toSecureArray() : array {
                return $this->toArray();
            }

            public function toSecureJson(): string {
                return $this->toJson();
            }
        };
    }

    public function getLogoutUri(string $id, XUri $returnUri) : ?XUri {
        return null;
    }

    public function getScopes() : array {
        return [];
    }
}
