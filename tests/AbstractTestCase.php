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

use modethirteen\AuthForge\Common\Http\Headers;
use modethirteen\Http\Mock\MockRequestMatcher;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class AbstractTestCase extends TestCase {

    /**
     * @var string|null - project root directory
     */
    private static $directory = null;

    /**
     * @return string|null
     */
    public static function getProjectRootDirectory() : ?string {
        return self::$directory;
    }

    /**
     * @param string $directory - project root directory
     */
    public static function initialize(string $directory) : void {
        self::$directory = $directory;
    }

    public function setUp() {
        MockRequestMatcher::setIgnoredHeaderNames([
            Headers::HEADER_CONTENT_LENGTH
        ]);
    }

    /**
     * @param string $class
     * @return MockObject
     */
    protected function newMock(string $class) : MockObject {
        return $this->getMockBuilder($class)
            ->setMethods(get_class_methods($class))
            ->disableOriginalConstructor()
            ->getMock();
    }
}
