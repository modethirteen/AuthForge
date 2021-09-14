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
namespace modethirteen\AuthForge\ServiceProvider\Saml;

use DOMDocument;
use DOMElement;
use DOMNodeList;
use DOMXPath;
use Exception;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentCannotWriteTextException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentNoElementToSignException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentSchemaValidationException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentSignatureException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentSignatureValidationException;
use modethirteen\Crypto\CryptoKeyInterface;
use modethirteen\TypeEx\BoolEx;
use modethirteen\TypeEx\StringEx;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class Document extends DOMDocument {
    const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
    const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
    const NS_SOAP = 'http://schemas.xmlsoap.org/soap/envelope/';
    const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
    const NS_XS = 'http://www.w3.org/2001/XMLSchema';
    const NS_XSI = 'http://www.w3.org/2001/XMLSchema-instance';
    const NS_XENC = 'http://www.w3.org/2001/04/xmlenc#';
    const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * @var array<string, string>
     */
    private array $namespaces;

    /**
     * @var string
     */
    private string $xsd;

    /**
     * @param string $xsd - xsd path for validation
     * @param array<string, string> $namespaces
     */
    final public function __construct(string $xsd, array $namespaces = []) {
        parent::__construct();
        $this->xsd = $xsd;
        $this->namespaces = $namespaces;
    }

    /**
     * Extracts nodes from the Document
     *
     * @param string $query -  xpath expresion
     * @param DOMElement|null $context - Context Node (DOMElement)
     * @return DOMNodeList - The queried nodes
     */
    public function query(string $query, DOMElement $context = null) : DOMNodeList {
        $xpath = new DOMXPath($this);
        foreach($this->namespaces as $prefix => $namespace) {
            $xpath->registerNamespace($prefix, $namespace);
        }

        /** @var DOMNodeList|bool $result */
        $result = $context !== null ? $xpath->query($query, $context) : $xpath->query($query);
        return $result instanceof DOMNodeList ? $result : new DOMNodeList();
    }

    /**
     * Format, normalize, and remove whitespace
     *
     * @return static
     * @throws SamlDocumentCannotWriteTextException
     */
    public function toFormattedDocument() : object  {
        $doc = new static($this->xsd, $this->namespaces);
        $xml = $this->saveXML();
        if($xml === false) {
            throw new SamlDocumentCannotWriteTextException($doc);
        }
        $xml = str_replace("\n", '', $xml);
        $xml = preg_replace('/>\s+</', '><', $xml);
        $doc->loadXML(trim($xml));
        $doc->preserveWhiteSpace = false;
        $doc->formatOutput = true;
        return $doc;
    }

    /**
     * Validate document against SAML 2.0 schema and get collection of errors
     *
     * @throws SamlDocumentSchemaValidationException
     */
    public function validateSchema() : void {
        libxml_clear_errors();
        libxml_use_internal_errors(true);
        $oldEntityLoader = libxml_disable_entity_loader(false);
        $result = $this->schemaValidate($this->xsd);
        libxml_disable_entity_loader($oldEntityLoader);
        if(!$result) {
            $errors = [];
            foreach(libxml_get_errors() as $error) {
                $errors[] = "[Line {$error->line}, Column {$error->column}] $error->message";
            }
            throw new SamlDocumentSchemaValidationException($errors);
        }
    }

    /**
     * @param CryptoKeyInterface $certificate
     * @throws SamlDocumentSignatureValidationException
     */
    public function validateSignature(CryptoKeyInterface $certificate) : void {
        $objXMLSecDSig = new XMLSecurityDSig();
        $objXMLSecDSig->idKeys = ['ID'];
        try {
            $objDSig = $objXMLSecDSig->locateSignature($this);
        } catch(Exception $e) {
            $objDSig = null;
        }

        // failed validation, depending on downstream logic, returns null or false
        if(!BoolEx::boolify($objDSig)) {
            throw new SamlDocumentSignatureValidationException($certificate, 'Cannot locate Signature node');
        }
        $objKey = $objXMLSecDSig->locateKey();

        // failed validation, depending on downstream logic, returns null or false
        if(!BoolEx::boolify($objKey)) {
            throw new SamlDocumentSignatureValidationException($certificate, 'Cannot locate a valid signing key');
        }
        try {
            $objXMLSecDSig->canonicalizeSignedInfo();
            $objXMLSecDSig->validateReference();
            XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);
            $objKey->loadKey($certificate->toString(), false, true);
            $result = $objXMLSecDSig->verify($objKey);
        } catch(Exception $e) {
            throw new SamlDocumentSignatureValidationException($certificate, $e->getMessage());
        }
        if((is_bool($result) && $result === false) || $result !== 1) {
            $error = StringEx::stringify(openssl_error_string());
            if(!StringEx::isNullOrEmpty($error)) {
                throw new SamlDocumentSignatureValidationException($certificate, "Signature validation failed with {$error}");
            } else {
                throw new SamlDocumentSignatureValidationException($certificate, 'Signature validation failed');
            }
        }
    }

    /**
     * @param string $prefix - namespace prefix (ex: md)
     * @param string $namespace - namespace uri (ex: urn:oasis:names:tc:SAML:2.0:metadata)
     * @return static
     * @throws SamlDocumentCannotWriteTextException
     */
    public function withNamespace(string $prefix, string $namespace) : object {
        $doc = $this->clone();
        $doc->namespaces[$prefix] = $namespace;
        return $doc;
    }

    /**
     * Returns an instance with an element of the document signed
     *
     * @param CryptoKeyInterface $key - private signing key
     * @param CryptoKeyInterface $certificate - x509 certificate
     * @param string|null $query - if supplied, xpath will be used to locate the document element to sign
     * @return static
     * @throws SamlDocumentSignatureException
     * @throws SamlDocumentNoElementToSignException
     * @throws SamlCannotLoadCryptoKeyException
     * @throws SamlDocumentCannotWriteTextException
     */
    public function withSignature(CryptoKeyInterface $key, CryptoKeyInterface $certificate, string $query = null) : object {
        $doc = $this->clone();
        try {

            // NOTE (modethirteen, 20200110): can we support signing algorithms besides sha1?
            // sha1 is the only digest algorithm defined in XMLDSIG-CORE <https://www.w3.org/TR/xmlsec-algorithms/#bib-XMLDSIG-CORE1>
            $securityKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, ['type' => 'private']);
            $securityKey->loadKey($key->toString(), false);
        } catch(Exception $e) {
            throw new SamlCannotLoadCryptoKeyException($key, $e->getMessage());
        }

        // get the element we should sign
        if($query !== null) {
            $elements = $doc->query($query);
            if($elements->length === 0) {
                throw new SamlDocumentNoElementToSignException($query);
            }
            $element = $elements->item(0);
        } else {
            $element = $doc->firstChild;
        }

        // sign the doc with our private key
        $dsig = new XMLSecurityDSig();
        try {
            $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        } catch(Exception $e) {
            throw new SamlDocumentSignatureException($key, $e->getMessage());
        }
        $dsig->addReferenceList(
            [$element],
            XMLSecurityDSig::SHA1,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N],
            ['id_name' => 'ID']
        );
        $dsig->sign($securityKey);

        // add the certificate to the signature
        $dsig->add509Cert($certificate->toString(), true);
        $insertBefore = $element->firstChild;
        if($element instanceof DOMElement && in_array($element->tagName, [
            'samlp:AuthnRequest',
            'samlp:Response',
            'samlp:LogoutRequest',
            'samlp:LogoutResponse'
        ])) {

            // TODO (modethirteen, 20200110: there seems to be a DOM traversal-related defect here when trying to inject a signature after an issuer element
            $issuerNodes = $this->query("/{$element->tagName}/saml:Issuer");
            if($issuerNodes->length === 1) {
                $insertBefore = $issuerNodes->item(0)->nextSibling;
            }
        }

        // add the signature and return new doc
        $dsig->insertSignature($element, $insertBefore);
        return $doc;
    }

    /**
     * @return static
     * @throws SamlDocumentCannotWriteTextException
     */
    private function clone() : object {
        $doc = new static($this->xsd);
        $doc->namespaces = $this->namespaces;
        $doc->xsd = $this->xsd;
        $xml = $this->saveXML();
        if($xml === false) {
            throw new SamlDocumentCannotWriteTextException($this);
        }
        $doc->loadXML($xml);
        return $doc;
    }
}
