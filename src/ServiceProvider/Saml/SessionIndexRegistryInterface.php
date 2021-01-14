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

interface SessionIndexRegistryInterface {

    /**
     * @param string $nameId
     * @param string $sessionIndex
     * @return bool
     */
    public function dirtySessionIndex(string $nameId, string $sessionIndex) : bool;

    /**
     * @param string $nameId
     * @return string|null
     */
    public function getSessionIndex(string $nameId) : ?string;

    /**
     * @param string $nameId
     * @return bool
     */
    public function isSessionIndexDirty(string $nameId) : bool;

    /**
     * @param string $nameId
     * @return bool
     */
    public function removeSessionIndex(string $nameId) : bool;

    /**
     * @param string $nameId
     * @param string $sessionIndex
     * @return bool
     */
    public function setSessionIndex(string $nameId, string $sessionIndex) : bool;
}
