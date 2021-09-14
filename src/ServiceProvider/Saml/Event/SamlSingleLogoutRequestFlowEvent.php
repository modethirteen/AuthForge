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
namespace modethirteen\AuthForge\ServiceProvider\Saml\Event;

use DateTimeInterface;
use modethirteen\AuthForge\Common\Event\AbstractEvent;
use modethirteen\AuthForge\Common\Utility\ArrayEx;

class SamlSingleLogoutRequestFlowEvent extends AbstractEvent  {

    /**
     * @var string
     */
    private string $username;

    /**
     * @var string[]
     */
    private array $sessionIndexes;

    /**
     * @param DateTimeInterface $dateTime
     * @param string $username
     * @param string[] $sessionIndexes
     */
    public function __construct(DateTimeInterface $dateTime, string $username, array $sessionIndexes) {
        parent::__construct($dateTime);
        $this->username = $username;
        $this->sessionIndexes = $sessionIndexes;
    }

    /**
     * @return string[]
     */
    public function getSessionIndexes() : array {
        return $this->sessionIndexes;
    }

    /**
     * @return string
     */
    public function getUsername() : string {
        return $this->username;
    }

    /**
     * {@inheritDoc}
     */
    public function toArray() : array {
        return ArrayEx::merge([
            'SessionIndexes' => $this->getSessionIndexes(),
            'Username' => $this->getUsername()
        ], parent::toArray());
    }
}
