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
namespace modethirteen\AuthForge\Tests;

use modethirteen\Http\Mock\MockPlug;
use PHPUnit\Framework\TestCase;

class MockPlugEx {

    /**
     * Send global MockPlug details to console
     *
     * @param TestCase $test
     * @param bool $isError - send details to stderr (default: false, send to stdout)
     */
    public static function writeMockPlugDetailsToConsole(TestCase $test, bool $isError = false) : void {
        $stream = fopen($isError ? 'php://stderr' : 'php://stdout', 'w');

        // mock requests
        $calls = MockPlug::getNormalizedCallData();

        // mocks
        $mocks = [];
        foreach(MockPlug::getNormalizedMockData() as $id => $mock) {
            if(isset($calls[$id])) {
                $mock['request'] = $id;
                $mocks[] = $mock;
            } else {
                $mocks[] = $mock;
            }
        }

        // write
        $json = json_encode($mocks, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        fwrite($stream, "---\n\nMockPlug Details for {$test->getName()}\n\n");
        fwrite($stream, "Mocks: {$json}\n\n");
        $json = json_encode($calls, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        fwrite($stream, "Calls: {$json}\n\n---");
        fclose($stream);
    }
}
