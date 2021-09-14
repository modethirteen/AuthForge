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

use Closure;
use modethirteen\AuthForge\Common\Utility\ArrayEx;
use modethirteen\XArray\MutableXArray;
use Psr\Log\AbstractLogger;

abstract class AbstractContextLogger extends AbstractLogger implements ContextLoggerInterface {

    /**
     * @var Closure[]
     */
    private $handlers = [];

    /**
     * @param Closure $handler - <$handler(MutableXArray $context) : void> : insert context for all subsequent logged messages
     */
    final public function addContextHandler(Closure $handler) : void {
        $this->handlers[] = $handler;
    }

    final public function log($level, $message, array $context = []) {
        $context = ArrayEx::merge($this->getBaseContext(), $context);
        $this->write($level, LoggerStringEx::interpolate($message, $context), $context);
    }

    /**
     * @param mixed $level
     * @param string $message
     * @param array $context
     */
    abstract protected function write($level, string $message, array $context) : void;

    /**
     * @return array
     */
    private function getBaseContext() : array {
        $context = [];
        foreach($this->handlers as $handler) {
            $handler(new MutableXArray($context));
        }
        return $context;
    }
}
