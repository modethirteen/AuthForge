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
namespace modethirteen\AuthForge\Common\Utility;

use DateTimeImmutable;
use DateTimeInterface;

class DateTimeImmutableEx extends DateTimeImmutable implements DateTimeInterface {

    /**
     * @param DateTimeInterface $dateTime
     * @return DateTimeImmutableEx|null
     */
    public static function fromDateTime(DateTimeInterface $dateTime) : ?DateTimeImmutableEx {
        $instance = (new DateTimeImmutableEx())->setTimestamp($dateTime->getTimestamp());
        return $instance instanceof DateTimeImmutableEx ? $instance : null;
    }

    /**
     * @param string $timestamp - ISO8061 timestamp (yyyy-MM-ddTHH:mm:ssZ)
     * @return DateTimeImmutableEx|null
     */
    public static function fromISO8601(string $timestamp) : ?DateTimeImmutableEx {
        $matches = [];

        // we use a very strict regex to parse the timestamp
        $exp1 = '/^(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)';
        $exp2 = 'T(\\d\\d):(\\d\\d):(\\d\\d)(?:\\.\\d+)?Z$/D';
        if(preg_match($exp1 . $exp2, $timestamp, $matches) === 0) {
            return null;
        }

        /**
         * extract the different components of the time from the
         * matches in the regex. intval will ignore leading zeroes
         * in the string.
         */
        $year = intval($matches[1]);
        $month = intval($matches[2]);
        $day = intval($matches[3]);
        $hour = intval($matches[4]);
        $minute = intval($matches[5]);
        $second = intval($matches[6]);
        $time = gmmktime($hour, $minute, $second, $month, $day, $year);
        if($time === false) {
            return null;
        }
        $instance = (new DateTimeImmutableEx())->setTimestamp($time);
        return $instance instanceof DateTimeImmutableEx ? $instance : null;
    }

    /**
     * Standard ISO8601 duration format (for xs:duration XML schema)
     *
     * @param int $seconds
     * @return string
     */
    public static function toISO8601Duration(int $seconds) : string {
        $days = floor($seconds / 86400);
        $seconds = $seconds % 86400;
        $hours = floor($seconds / 3600);
        $seconds = $seconds % 3600;
        $minutes = floor($seconds / 60);
        $seconds = $seconds % 60;
        return sprintf('P%dDT%dH%dM%dS', $days, $hours, $minutes, $seconds);
    }

    /**
     * Standard UTC time: "yyyy-MM-ddTHH:mm:ssZ"
     *
     * @return string
     */
    public function toISO8601() : string {
        return gmdate('Y-m-d', $this->getTimestamp()) . 'T' . gmdate('H:i:s', $this->getTimestamp()) . 'Z';
    }
}
