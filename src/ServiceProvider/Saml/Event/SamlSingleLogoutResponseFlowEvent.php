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

class SamlSingleLogoutResponseFlowEvent extends AbstractEvent  {

    /**
     * @var string
     */
    private $status;

    /**
     * @param DateTimeInterface $dateTime
     * @param string $status
     */
    public function __construct(DateTimeInterface $dateTime, string $status) {
        parent::__construct($dateTime);
        $this->status = $status;
    }

    /**
     * @return string
     */
    public function getStatus() : string {
        return $this->status;
    }

    /**
     * {@inheritDoc}
     */
    public function toArray() : array {
        return ArrayEx::merge([
            'Status' => $this->status
        ], parent::toArray());
    }
}
