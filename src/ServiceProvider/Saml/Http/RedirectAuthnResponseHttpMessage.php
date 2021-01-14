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

use modethirteen\AuthForge\Common\Exception\ServerRequestInterfaceParsedBodyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlHttpMessageValidationException;
use modethirteen\Http\Exception\MalformedUriException;

class RedirectAuthnResponseHttpMessage extends AbstractAuthnResponseHttpMessage implements AuthnResponseHttpMessageInterface {
    use RedirectHttpMessageSignatureTrait;

    protected static function getHttpMessageParam() : string {
        return HttpMessageInterface::PARAM_SAML_RESPONSE;
    }

    protected static function isHttpMessageDeflated() : bool {
        return true;
    }

    /**
     * @throws SamlCannotLoadCryptoKeyException
     * @throws SamlHttpMessageValidationException
     * @throws ServerRequestInterfaceParsedBodyException
     * @throws MalformedUriException
     */
    protected function validateSignature() : void {
        $isSignatureAvailable = $this->request->getParam(HttpMessageInterface::PARAM_SAML_SIGNATURE) !== null;
        if($this->saml->isStrictValidationRequired()) {
            $errors = [];
            if($this->saml->isAssertionSignatureRequired() && !$isSignatureAvailable) {
                $errors[] = 'AuthnResponse/Assertion is not signed';
            }
            if($this->saml->isMessageSignatureRequired() && !$isSignatureAvailable) {
                $errors[] = 'AuthnResponse is not signed';
            }
            if(!empty($errors)) {
                throw new SamlHttpMessageValidationException(implode(' and ', $errors));
            }
        }
        if($isSignatureAvailable && !$this->isValidSignedMessage($this->saml->getIdentityProviderX509Certificate(), $this->request)) {
            throw new SamlHttpMessageValidationException('AuthnResponse signature validation failed');
        }
    }
}
