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

class SamlDocumentSchemaValidationException extends SamlException {

    /**
     * @var string[]
     */
    private $errors;

    /**
     * @param string[] $errors
     */
    public function __construct(array $errors) {
        parent::__construct('Document cannot be validated against http://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd');
        $this->errors = array_map('trim', $errors);
    }

    /**
     * @return string[]
     */
    public function getErrors() : array {
        return $this->errors;
    }
}
