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
namespace modethirteen\AuthForge\Common\Exception;

class ServerRequestInterfaceParsedBodyException extends AuthException {

    /**
     * @var mixed
     */
    private $body;

    /**
     * @param mixed $body
     */
    public function __construct($body) {
        parent::__construct('AuthForge expects the value type of a server request parsed body to be array<string, string>');
        $this->body = $body;
    }

    /**
     * @return mixed
     */
    public function getParsedBody() {
        return $this->body;
    }
}
