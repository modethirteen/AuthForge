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

use Exception;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotGenerateSignatureException;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\Crypto\CryptoKeyInterface;
use modethirteen\Http\XUri;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class SamlHttpMessageUri extends XUri {

    /**
     * @param CryptoKeyInterface $key - private signing key
     * @param string $algo - XMLDSIG-CORE digest algorithm (default: http://www.w3.org/2000/09/xmldsig#rsa-sha1)
     * @return static
     * @throws SamlCannotLoadCryptoKeyException
     * @throws SamlCannotGenerateSignatureException
     */
    public function withSignature(CryptoKeyInterface $key, string $algo = XMLSecurityKey::RSA_SHA1) : object {
        $msg = '';

        // TODO (modethirteen, 20200110): prevent a URI from including both SAMLResponse and SAMLRequest query params
        $request = $this->getQueryParam(HttpMessageInterface::PARAM_SAML_REQUEST);
        if($request !== null) {
            $msg = 'SAMLRequest=' . urlencode($request);
        }
        $response = $this->getQueryParam(HttpMessageInterface::PARAM_SAML_RESPONSE);
        if($response !== null) {
            $msg = 'SAMLResponse=' . urlencode($response);
        }
        if($msg === '') {
            throw new SamlCannotGenerateSignatureException();
        }
        $relayState = $this->getQueryParam(HttpMessageInterface::PARAM_SAML_RELAYSTATE);
        if($relayState !== null) {
            $msg .= '&RelayState=' . urlencode($relayState);
        }
        $msg .= '&SigAlg=' . urlencode($algo);
        try {
            $signer = new XMLSecurityKey($algo, ['type' => 'private']);
            $signer->loadKey($key->toString(), false);
        } catch(Exception $e) {
            throw new SamlCannotLoadCryptoKeyException($key, $e->getMessage());
        }
        $signature = $signer->signData($msg);
        if($signature === null) {
            throw new SamlCannotGenerateSignatureException();
        }
        return $this
            ->withQueryParam(HttpMessageInterface::PARAM_SAML_SIGALG, $algo)
            ->withQueryParam(HttpMessageInterface::PARAM_SAML_SIGNATURE, base64_encode($signature));
    }
}