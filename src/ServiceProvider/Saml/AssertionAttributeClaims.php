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

use modethirteen\AuthForge\Common\Identity\AbstractClaims;
use modethirteen\AuthForge\Common\Identity\ClaimsInterface;
use modethirteen\XArray\Serialization\JsonSerializer;
use modethirteen\XArray\XArray;

class AssertionAttributeClaims extends AbstractClaims implements ClaimsInterface {

    /**
     * @var string|null
     */
    private ?string $username = null;

    public function getUsername() : ?string {
        return $this->username;
    }

    public function toJson() : string {
        return (new XArray($this->toArray()))
            ->withSerializer(new JsonSerializer())
            ->toString();
    }

    public function toSecureArray() : array {

        // TODO (modethirteen, 20190426): filter saml attributes for privacy
        return $this->toArray();
    }

    public function toSecureJson() : string {
        return (new XArray($this->toSecureArray()))
            ->withSerializer(new JsonSerializer())
            ->toString();
    }

    public function toArray() : array {
        $items = [];
        foreach(parent::toArray() as $name => $value) {

            // flatten assertion claims if only a single value in attribute node
            $items[$name] = (is_array($value) && !empty($value) && count($value) === 1) ? $value[0] : $value;
        }
        return $items;
    }

    /**
     * @param string $nameId
     * @return static
     */
    public function withNameId(string $nameId) : object {
        $instance = clone $this;
        $instance->username = $nameId;
        return $instance;
    }
}
