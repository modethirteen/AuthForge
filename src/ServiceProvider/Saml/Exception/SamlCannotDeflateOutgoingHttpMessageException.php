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
namespace modethirteen\AuthForge\ServiceProvider\Saml\Exception;

class SamlCannotDeflateOutgoingHttpMessageException extends SamlException {

    /**
     * @var string
     */
    private string $data;

    /**
     * @param string $data
     */
    public function __construct(string $data) {
        parent::__construct('Cannot deflate outgoing HTTP message');
        $this->data = $data;
    }

    /**
     * @return string
     */
    public function getData() : string {
        return $this->data;
    }
}
