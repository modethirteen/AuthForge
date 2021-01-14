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
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageValidationException;
use modethirteen\Http\Exception\MalformedUriException;
use modethirteen\TypeEx\StringEx;

class RedirectLogoutResponseHttpMessage extends AbstractHttpMessage implements HttpMessageInterface {
    use RedirectHttpMessageSignatureTrait;

    protected static function getHttpMessageParam() : string {
        return HttpMessageInterface::PARAM_SAML_RESPONSE;
    }

    protected static function isHttpMessageDeflated() : bool {
        return true;
    }

    /**
     * @return string
     */
    public function getId() : string {
        return $this->document->documentElement->getAttribute('ID');
    }

    /**
     * @return string
     */
    public function getInResponseToId() : string {
        return $this->document->documentElement->getAttribute('InResponseTo');
    }

    /**
     * @return string|null $issuer
     */
    public function getIssuer() : ?string {
        $issuer = null;
        $issuerNodes = $this->document->query('/samlp:LogoutResponse/saml:Issuer');
        if($issuerNodes->length === 1) {
            $issuer = $issuerNodes->item(0)->textContent;
        }
        return $issuer;
    }

    /**
     * @return string
     */
    public function getStatus() : ?string {
        $status = null;
        $entries = $this->document->query('/samlp:LogoutResponse/samlp:Status/samlp:StatusCode');
        if($entries->length !== 0) {
            $element = $entries->item(0);
            $status = $element instanceof DOMElement ? $element->getAttribute('Value') : null;
        }
        return $status;
    }

    /**
     * {@inheritDoc}
     * @throws SamlDocumentSchemaValidationException
     * @throws SamlHttpMessageValidationException
     * @throws SamlCannotLoadCryptoKeyException
     * @throws ServerRequestInterfaceParsedBodyException
     * @throws MalformedUriException
     */
    public function validate(string $requestId = null) : void {

        // validate signature
        $isSignatureAvailable = $this->request->getParam(HttpMessageInterface::PARAM_SAML_SIGNATURE) !== null;
        if($isSignatureAvailable && !$this->isValidSignedMessage($this->saml->getIdentityProviderX509Certificate(), $this->request)) {
            throw new SamlHttpMessageValidationException('LogoutResponse signature validation failed');
        }
        if($this->saml->isStrictValidationRequired()) {
            $this->document->validateSchema();

            // check if the InResponseTo matches the ID of the LogoutRequest (optional)
            $responseInResponseTo = $this->getInResponseToId() ? $this->getInResponseToId() : null;
            if($requestId !== null && $responseInResponseTo !== null && $requestId !== $responseInResponseTo) {
                throw new SamlHttpMessageValidationException('LogoutResponse/@InResponseTo does not match AuthnRequest/@ID', [
                    'InResponseTo' => $responseInResponseTo,
                    'LogoutRequestId' => $requestId
                ]);
            }

            // check issuer (optional)
            $identityProviderEntityId = $this->saml->getIdentityProviderEntityId();
            $issuer = $this->getIssuer();
            if(!StringEx::isNullOrEmpty($issuer) && $issuer !== $identityProviderEntityId) {
                throw new SamlHttpMessageValidationException('LogoutResponse/Issuer contains an unknown identity provider id', [
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
                        throw new SamlHttpMessageValidationException('LogoutResponse/@Destination does not match the current request URL', [
                            'Destination' => $destination,
                            'RequestUrl' => $currentHref
                        ]);
                    }
                }
            }

            // signature required? (optional)
            if($this->saml->isMessageSignatureRequired()) {
                if(!$isSignatureAvailable) {
                    throw new SamlHttpMessageValidationException('LogoutResponse is not signed');
                }
            }
        }
    }
}
