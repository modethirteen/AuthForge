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
namespace modethirteen\AuthForge\Common\Event;

use DateTimeInterface;
use modethirteen\AuthForge\Common\Utility\DateTimeImmutableEx;
use Psr\EventDispatcher\StoppableEventInterface;
use Symfony\Contracts\EventDispatcher\Event;

abstract class AbstractEvent extends Event implements StoppableEventInterface {

    /**
     * @var DateTimeInterface
     */
    private DateTimeInterface $dateTime;

    /**
     * @param DateTimeInterface $dateTime
     */
    public function __construct(DateTimeInterface $dateTime) {
        $this->dateTime = $dateTime;
    }

    /**
     * @return DateTimeInterface
     */
    public function getDateTime() : DateTimeInterface {
        return $this->dateTime;
    }

    /**
     * @return array
     */
    public function toArray() : array {
        return [
            'DateTime' => DateTimeImmutableEx::fromDateTime($this->getDateTime())->toISO8601()
        ];
    }
}
