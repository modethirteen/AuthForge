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
namespace modethirteen\AuthForge\Common\Identity;

use modethirteen\TypeEx\DictionaryInterface;

interface ClaimsInterface extends DictionaryInterface {

    /**
     * @param string $name
     * @return string|null
     */
    public function getClaim(string $name) : ?string;

    /**
     * @param string $name
     * @return array|null
     */
    public function getClaims(string $name) : ?array;

    /**
     * @return string|null
     */
    public function getUsername() : ?string;

    /**
     * @return string
     */
    public function toJson() : string;

    /**
     * return claim collection that is safe to store by removing potential replay attack data
     *
     * @return array
     */
    public function toSecureArray() : array;

    /**
     * return claim collection that is safe to store by removing potential replay attack data
     *
     * @return string
     */
    public function toSecureJson() : string;
}
