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

use modethirteen\AuthForge\ServiceProvider\Saml\Document;

class SamlDocumentCannotWriteTextException extends SamlException {

    /**
     * @var Document
     */
    private Document $document;

    /**
     * @param Document $document
     */
    public function __construct(Document $document) {
        parent::__construct('DOM structure cannot be written to XML text');
        $this->document = $document;
    }

    /**
     * @return Document
     */
    public function getDocument() : Document {
        return $this->document;
    }
}
