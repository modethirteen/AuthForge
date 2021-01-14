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
namespace modethirteen\AuthForge\ServiceProvider\Saml\Http;

use DOMElement;
use modethirteen\AuthForge\ServiceProvider\Saml\Document;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentSignatureValidationException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageValidationException;

class PostAuthnResponseHttpMessage extends AbstractAuthnResponseHttpMessage implements AuthnResponseHttpMessageInterface {

    protected static function getHttpMessageParam() : string {
        return HttpMessageInterface::PARAM_SAML_RESPONSE;
    }

    protected static function isHttpMessageDeflated() : bool {
        return false;
    }

    /**
     * @throws SamlDocumentSignatureValidationException
     * @throws SamlHttpMessageValidationException
     */
    protected function validateSignature() : void {

        // all nodes that need to signature validation
        $signedElements = [];
        $signatureNodes = $this->isDocumentEncrypted()
            ? $this->decryptedDocument->getElementsByTagName('Signature')
            : $this->document->getElementsByTagName('Signature');
        foreach($signatureNodes as $signatureNode) {

            /** @var DomElement $signatureNode */
            $signedNode = $signatureNode->parentNode;
            $tag = $signedNode->tagName;

            /** @noinspection PhpUndefinedFieldInspection */
            if($signedNode->localName === 'Assertion' && $signedNode->namespaceURI === Document::NS_SAML) {

                // fixup ADFS assertion tag, it includes correct namespace uri but does not have prefix (and doesn't match the signed elements check below)
                $tag = 'saml:Assertion';
            }
            $signedElements[] = $tag;
        }

        // validate signature
        if($this->saml->isStrictValidationRequired()) {
            $errors = [];
            if($this->saml->isAssertionSignatureRequired() && !in_array('saml:Assertion', $signedElements)) {
                $errors[] = 'AuthnResponse/Assertion is not signed';
            }
            if($this->saml->isMessageSignatureRequired() && !in_array('samlp:Response', $signedElements)) {
                $errors[] = 'AuthnResponse is not signed';
            }
            if(!empty($errors)) {
                throw new SamlHttpMessageValidationException(implode(' and ', $errors));
            }
        }
        if(!empty($signedElements)) {

            // Only validates the first sign found
            // TODO (modethirteen, 20201121): investigate how to handle signed message with encrypted assertion
            if(in_array('samlp:Response', $signedElements)) {
                $documentToValidate = $this->document;
            } else {
                $documentToValidate = $this->isDocumentEncrypted() ? $this->decryptedDocument : $this->document;
            }
            $documentToValidate->validateSignature($this->saml->getIdentityProviderX509Certificate());
        }
    }
}
