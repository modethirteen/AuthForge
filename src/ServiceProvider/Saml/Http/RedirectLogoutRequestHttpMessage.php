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
use modethirteen\AuthForge\Common\Exception\ServerRequestInterfaceParsedBodyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlDocumentSchemaValidationException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionAlgorithmMismatchException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionCannotLocateKeyInfoException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageElementDecryptionUnknownKeySizeException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageLogoutRequestDoesNotContainNameIdException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageValidationException;
use modethirteen\Http\Exception\MalformedUriException;
use modethirteen\TypeEx\StringEx;

class RedirectLogoutRequestHttpMessage extends AbstractHttpMessage implements HttpMessageInterface {
    use RedirectHttpMessageSignatureTrait;

    protected static function getHttpMessageParam() : string {
        return HttpMessageInterface::PARAM_SAML_REQUEST;
    }

    protected static function isHttpMessageDeflated() : bool {
        return true;
    }

    /**
     * @var array|null
     */
    private $nameIdData = null;

    /**
     * @return string
     */
    public function getId() : string {
        return $this->document->documentElement->getAttribute('ID');
    }

    /**
     * @return string|null
     */
    public function getIssuer() : ?string {
        $issuer = null;
        $issuerNodes = $this->document->query('/samlp:LogoutRequest/saml:Issuer');
        if($issuerNodes->length === 1) {
            $issuer = $issuerNodes->item(0)->textContent;
        }
        return $issuer;
    }

    /**
     * @return string
     * @throws SamlCannotLoadCryptoKeyException
     * @throws SamlHttpMessageElementDecryptionAlgorithmMismatchException
     * @throws SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement
     * @throws SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException
     * @throws SamlHttpMessageElementDecryptionCannotLocateKeyInfoException
     * @throws SamlHttpMessageElementDecryptionException
     * @throws SamlHttpMessageElementDecryptionUnknownKeySizeException
     * @throws SamlHttpMessageLogoutRequestDoesNotContainNameIdException
     */
    public function getNameId() : string {
        $nameIdData = $this->getNameIdData();
        return $nameIdData['Value'];
    }

    /**
     * @return array
     */
    public function getSessionIndexes() : array {
        $sessionIndexes = [];
        $sessionIndexNodes = $this->document->query('/samlp:LogoutRequest/samlp:SessionIndex');
        foreach($sessionIndexNodes as $sessionIndexNode) {
            $sessionIndexes[] = $sessionIndexNode->textContent;
        }
        return $sessionIndexes;
    }

    /**
     * {@inheritDoc}
     * @throws SamlHttpMessageValidationException
     * @throws SamlDocumentSchemaValidationException
     * @throws SamlCannotLoadCryptoKeyException
     * @throws ServerRequestInterfaceParsedBodyException
     * @throws MalformedUriException
     */
    public function validate(string $requestId = null) : void {

        // validate signature
        $isSignatureAvailable = $this->request->getParam(HttpMessageInterface::PARAM_SAML_SIGNATURE) !== null;
        if($isSignatureAvailable && !$this->isValidSignedMessage($this->saml->getIdentityProviderX509Certificate(), $this->request)) {
            throw new SamlHttpMessageValidationException('LogoutRequest signature validation failed');
        }
        if($this->saml->isStrictValidationRequired()) {
            $this->document->validateSchema();

            // check encryption (optional)
            if($this->saml->isNameIdEncryptionRequired()) {
                $encryptedIdNodes = $this->document->query('/samlp:LogoutRequest/saml:EncryptedID/xenc:EncryptedData');
                if($encryptedIdNodes->length === 0) {
                    throw new SamlHttpMessageValidationException('LogoutRequest/NameID is not encrypted');
                }
            }

            // check issuer (required)
            $identityProviderEntityId = $this->saml->getIdentityProviderEntityId();
            $issuer = $this->getIssuer();
            if(StringEx::isNullOrEmpty($issuer) || $issuer !== $identityProviderEntityId) {
                throw new SamlHttpMessageValidationException('LogoutRequest/Issuer contains an unknown identity provider id', [
                    'Issuer' => $issuer,
                    'IdentityProviderEntityId' => $identityProviderEntityId
                ]);
            }

            // check destination (optional, only base href + path is matched)
            $currentHref = self::getCurrentDestinationHref($this->request);
            if($this->document->documentElement->hasAttribute('Destination')) {
                $destination = $this->document->documentElement->getAttribute('Destination');
                if(!StringEx::isNullOrEmpty($destination)) {
                    if(rtrim($destination, '/') !== rtrim($currentHref, '/')) {
                        throw new SamlHttpMessageValidationException('LogoutRequest/@Destination does not match the current request URL', [
                            'Destination' => $destination,
                            'RequestUrl' => $currentHref
                        ]);
                    }
                }
            }

            // signature required? (optional)
            if($this->saml->isMessageSignatureRequired()) {
                if(!$isSignatureAvailable) {
                    throw new SamlHttpMessageValidationException('LogoutRequest is not signed');
                }
            }
        }
    }

    /**
     * @return array - Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
     * @throws SamlCannotLoadCryptoKeyException
     * @throws SamlHttpMessageElementDecryptionException
     * @throws SamlHttpMessageLogoutRequestDoesNotContainNameIdException
     * @throws SamlHttpMessageElementDecryptionAlgorithmMismatchException
     * @throws SamlHttpMessageElementDecryptionCannotLoadCipherFromEncryptedElement
     * @throws SamlHttpMessageElementDecryptionCannotLocateKeyAlgorithmException
     * @throws SamlHttpMessageElementDecryptionCannotLocateKeyInfoException
     * @throws SamlHttpMessageElementDecryptionUnknownKeySizeException
     */
    private function getNameIdData() : array {
        if($this->nameIdData === null) {
            $nameIdElement = null;
            $encryptedIdDataEntries = $this->document->query('/samlp:LogoutRequest/saml:EncryptedID/xenc:EncryptedData');
            if($encryptedIdDataEntries->length === 1) {
                $encryptedIdDataElement = $encryptedIdDataEntries->item(0);
                if($encryptedIdDataElement instanceof DOMElement) {
                    $nameIdElement = $this->getDecryptedElement($encryptedIdDataElement);
                }
            } else {
                $entries = $this->document->query('/samlp:LogoutRequest/saml:NameID');
                if($entries->length === 1) {
                    $nameIdElement = $entries->item(0);
                }
            }
            if($nameIdElement === null || !($nameIdElement instanceof DOMElement)) {
                throw new SamlHttpMessageLogoutRequestDoesNotContainNameIdException();
            }
            $nameIdData = [];
            $nameIdData['Value'] = $nameIdElement->nodeValue;
            foreach(['Format', 'SPNameQualifier', 'NameQualifier'] as $attr) {
                if($nameIdElement->hasAttribute($attr)) {
                    $nameIdData[$attr] = $nameIdElement->getAttribute($attr);
                }
            }
            $this->nameIdData = $nameIdData;
        }
        return $this->nameIdData;
    }
}
