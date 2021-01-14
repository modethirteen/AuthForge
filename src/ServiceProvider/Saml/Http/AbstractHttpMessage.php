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
use Exception;
use modethirteen\AuthForge\Common\Exception\ServerRequestInterfaceParsedBodyException;
use modethirteen\AuthForge\Common\Http\ServerRequestEx;
use modethirteen\AuthForge\ServiceProvider\Saml\Document;
use modethirteen\AuthForge\ServiceProvider\Saml\DocumentFactoryInterface;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentCannotLoadTextException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageCannotParseHttpMessageException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionAlgorithmMismatchException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionCannotLocateKeyInfoException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionUnknownKeySizeException;
use modethirteen\AuthForge\ServiceProvider\Saml\SamlConfigurationInterface;
use modethirteen\Http\Exception\MalformedUriException;
use modethirteen\TypeEx\Exception\StringExCannotDecodeBase64StringException;
use modethirteen\TypeEx\StringEx;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;

abstract class AbstractHttpMessage implements HttpMessageInterface  {

    /**
     * @return string
     */
    abstract protected static function getHttpMessageParam() : string;

    /**
     * @return bool
     */
    abstract protected static function isHttpMessageDeflated() : bool;

    /**
     * @param ServerRequestEx $request
     * @return string
     * @throws MalformedUriException
     */
    protected static function getCurrentDestinationHref(ServerRequestEx $request) : string {
        $currentRequestUri = $request->getUri();
        $scheme = $currentRequestUri->getScheme();
        $href = StringEx::isNullOrEmpty($scheme) ? 'http://' : $scheme . '://';
        $href .= $currentRequestUri->getAuthority();
        $href .= $currentRequestUri->getPath();
        return $href;
    }

    /**
     * @var Document
     */
    protected $document;

    /**
     * @var DocumentFactoryInterface
     */
    protected $documentFactory;

    /**
     * @var string
     */
    protected $message;

    /**
     * @var ServerRequestEx
     */
    protected $request;

    /**
     * @var SamlConfigurationInterface
     */
    protected $saml;

    /**
     * @param SamlConfigurationInterface $saml
     * @param ServerRequestEx $request
     * @param DocumentFactoryInterface $documentFactory
     * @throws SamlHttpMessageCannotParseHttpMessageException
     */
    public function __construct(
        SamlConfigurationInterface $saml,
        ServerRequestEx $request,
        DocumentFactoryInterface $documentFactory
    ) {
        $this->saml = $saml;
        $this->request = $request;
        $this->documentFactory = $documentFactory;
        try {
            $message = StringEx::stringify($this->request->getParam(static::getHttpMessageParam()));
            if(StringEx::isNullOrEmpty($message)) {
                throw new SamlDocumentCannotLoadTextException($message);
            }
            try {
                $message = (new StringEx($message))->decodeBase64(true)->toString();
            } catch(StringExCannotDecodeBase64StringException $e) {
                throw new SamlDocumentCannotLoadTextException($message);
            }
            if(static::isHttpMessageDeflated()) {
                $inflated = gzinflate($message);
                if($inflated !== false) {
                    $message = $inflated;
                }
            }
            $this->message = $message;
            $this->document = $documentFactory->newMessageDocument($this->message);
        } catch(
            ServerRequestInterfaceParsedBodyException |
            SamlDocumentCannotLoadTextException $e
        ) {
            throw new SamlHttpMessageCannotParseHttpMessageException();
        }
    }

    public function toString() : string {
        return $this->message;
    }

    /**
     * @param DOMElement $encryptedElement
     * @return DOMElement|null
     * @throws SamlHttpMessageElementDecryptionException
     * @throws SamlHttpMessageElementDecryptionAlgorithmMismatchException
     * @throws SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement
     * @throws SamlHttpMessageElementDecryptionUnknownKeySizeException
     * @throws SamlHttpMessageElementDecryptionAlgorithmMismatchException
     * @throws SamlHttpMessageElementDecryptionCannotLocateKeyInfoException
     * @throws SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException
     * @throws SamlCannotLoadCryptoKeyException
     */
    protected function getDecryptedElement(DOMElement $encryptedElement) : ?DOMElement {
        $privateKey = $this->saml->getServiceProviderPrivateKey();
        try {
            $securityKey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, ['type' => 'private']);
            $securityKey->loadKey($privateKey !== null ? $privateKey->toString() : null);
        } catch(Exception $e) {
            throw new SamlCannotLoadCryptoKeyException($privateKey, $e->getMessage());
        }
        $enc = new XMLSecEnc();
        $enc->setNode($encryptedElement);
        $enc->type = $encryptedElement->getAttribute('Type');
        $symmetricKey = $enc->locateKey($encryptedElement);
        if($symmetricKey === null) {
            throw new SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException();
        }
        $symmetricKeyInfo = $enc->locateKeyInfo($symmetricKey);
        if($symmetricKeyInfo === null) {
            throw new SamlHttpMessageElementDecryptionCannotLocateKeyInfoException();
        }
        $securityKeyAlgorithm = $securityKey->getAlgorithm();
        if($symmetricKeyInfo->isEncrypted) {
            $symmetricKeyInfoAlgorithm = $symmetricKeyInfo->getAlgorithm();
            if($symmetricKeyInfoAlgorithm === XMLSecurityKey::RSA_OAEP_MGF1P && $securityKeyAlgorithm === XMLSecurityKey::RSA_1_5) {
                $securityKeyAlgorithm = XMLSecurityKey::RSA_OAEP_MGF1P;
            }
            if($securityKeyAlgorithm !== $symmetricKeyInfoAlgorithm) {
                throw new SamlHttpMessageElementDecryptionAlgorithmMismatchException();
            }
            $encryptedCtx = $symmetricKeyInfo->encryptedCtx;
            $symmetricKeyInfo->key = $securityKey->key;
            $keySize = $symmetricKey->getSymmetricKeySize();
            if($keySize === null) {

                // To protect against "key oracle" attacks
                throw new SamlHttpMessageElementDecryptionUnknownKeySizeException();
            }
            try {

                // XMLSecEnc::decryptKey returns string if replacement argument is not supplied
                /** @var string $key */
                $key = $encryptedCtx->decryptKey($symmetricKeyInfo);
            } catch(Exception $e) {
                throw new SamlHttpMessageElementDecryptionException($e->getMessage());
            }
            if(strlen($key) !== $keySize) {
                try {
                    $encryptedKey = $encryptedCtx->getCipherValue();
                } catch(Exception $e) {
                    throw new SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement($e->getMessage());
                }
                $pkey = openssl_pkey_get_details($symmetricKeyInfo->key);
                $pkey = sha1(serialize($pkey), true);
                $key = sha1($encryptedKey . $pkey, true);

                // make sure that the key has the correct length
                if(strlen($key) > $keySize) {
                    $key = substr($key, 0, $keySize);
                } else if(strlen($key) < $keySize) {
                    $key = str_pad($key, $keySize);
                }
            }
            try {
                $symmetricKey->loadKey($key);
            } catch(Exception $e) {
                throw new SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement($e->getMessage());
            }
        } else {
            $symmetricKeyAlgorithm = $symmetricKey->getAlgorithm();
            if($securityKeyAlgorithm !== $symmetricKeyAlgorithm) {
                throw new SamlHttpMessageElementDecryptionAlgorithmMismatchException();
            }
            $symmetricKey = $securityKey;
        }
        try {
            $decrypted = $enc->decryptNode($symmetricKey, false);
        } catch(Exception $e) {
            throw new SamlHttpMessageElementDecryptionException($e->getMessage());
        }

        /** @noinspection XmlUnusedNamespaceDeclaration */
        $doc = $this->documentFactory->newMessageDocument("<root xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">{$decrypted}</root>");
        $decryptedElement = $doc->firstChild->firstChild;
        return $decryptedElement instanceof DOMElement ? $decryptedElement : null;
    }
}
