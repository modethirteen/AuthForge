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

class ArrayEx {

    /**
     * Array merge that combines array leaf nodes without overwriting
     *
     * @see https://github.com/modethirteen/XArray/blob/main/src/XArray.php
     * @todo (modethirteen, 20201221): replace with \modethirteen\XArray\XArray::toMergedArray
     * @param array $first
     * @param array $second
     * @return array
     */
    public static function merge(array $first, array $second) : array {
        $merged = $first;
        foreach($second as $k => $v) {
            if(is_array($v) && isset($merged[$k]) && is_array($merged[$k])) {
                $merged[$k] = self::merge($merged[$k], $v);
            } else if(is_int($k)) {
                $merged[] = $v;
            } else {
                $merged[$k] = $v;
            }
        }
        return $merged;
    }

    /**
     * @see https://github.com/modethirteen/XArray/blob/main/src/XArray.php
     * @todo (modethirteen, 20201221): replace with \modethirteen\XArray\XArray::fromDelimited
     * @param string $delimiter
     * @param string $text
     * @return string[]
     */
    public static function newStringArrayFromDelimitedText(string $delimiter, string $text) : array {
        $pieces = explode($delimiter, $text);
        return !is_array($pieces) || empty($pieces) ? [] : array_filter(array_map('trim', $pieces));
    }
}
