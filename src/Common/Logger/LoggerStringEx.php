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
namespace modethirteen\AuthForge\Common\Logger;

use modethirteen\TypeEx\StringDictionary;
use modethirteen\TypeEx\StringEx;

class LoggerStringEx {

    /**
     * @param string $message
     * @param array<string|int, mixed> $context
     * @return string
     */
    public static function interpolate(string $message, array $context) : string {
        $replacements = new StringDictionary();
        foreach($context as $key => $value) {
            $key = StringEx::stringify($key);
            $replacements->set($key, StringEx::stringify($value,
                function() use ($key) : string {

                    // collections and objects are not supported in logging interpolation, return the original variable
                    return '{{' . trim($key) . '}}';
                })
            );
        }
        return (new StringEx($message))->interpolate($replacements)->toString();
    }
}
