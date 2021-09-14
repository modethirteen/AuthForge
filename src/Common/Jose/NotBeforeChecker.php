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
namespace modethirteen\AuthForge\Common\Jose;

use DateTimeInterface;
use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;

class NotBeforeChecker implements ClaimChecker {
    private const CLAIM_NAME = 'nbf';

    /**
     * @var int
     */
    private int $allowedTimeDrift;

    /**
     * @var DateTimeInterface
     */
    private DateTimeInterface $dateTime;

    /**
     * @param DateTimeInterface $dateTime
     * @param int $allowedTimeDrift
     */
    public function __construct(DateTimeInterface $dateTime, int $allowedTimeDrift = 0) {
        $this->dateTime = $dateTime;
        $this->allowedTimeDrift = $allowedTimeDrift;
    }

    public function checkClaim($value) : void {
        if(!is_int($value)) {
            throw new InvalidClaimException('"nbf" must be an integer.', self::CLAIM_NAME, $value);
        }
        if($this->dateTime->getTimestamp() < $value - $this->allowedTimeDrift) {
            throw new InvalidClaimException('The JWT can not be used yet.', self::CLAIM_NAME, $value);
        }
    }

    public function supportedClaim() : string {
        return self::CLAIM_NAME;
    }
}
