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
use modethirteen\AuthForge\Common\Exception\ServerRequestInterfaceParsedBodyException;
use modethirteen\AuthForge\Common\Http\ServerRequestEx;
use modethirteen\AuthForge\ServiceProvider\Saml\Exception\SamlCannotLoadCryptoKeyException;
use modethirteen\Crypto\CryptoKeyInterface;
use modethirteen\Http\Exception\MalformedUriException;
use modethirteen\TypeEx\Exception\StringExCannotDecodeBase64StringException;
use modethirteen\TypeEx\StringEx;
use RobRichards\XMLSecLibs\XMLSecurityKey;

trait RedirectHttpMessageSignatureTrait {

    /**
     * @param CryptoKeyInterface $certificate
     * @param ServerRequestEx $request
     * @return bool
     * @throws SamlCannotLoadCryptoKeyException
     * @throws MalformedUriException
     * @throws ServerRequestInterfaceParsedBodyException
     */
    protected function isValidSignedMessage(CryptoKeyInterface $certificate, ServerRequestEx $request) : bool {
        $requestSignature = $request->getParam(HttpMessageInterface::PARAM_SAML_SIGNATURE);
        if($requestSignature === null) {
            return false;
        }
        try {
            $requestSignature = (new StringEx($requestSignature))->decodeBase64();
        } catch(StringExCannotDecodeBase64StringException $e) {
            return false;
        }

        /*
         * Parse the query string. We need to do this ourselves from the original uri, so that we get access
         * to the raw (urlencoded) values. This is required because different software
         * can urlencode to different values.
         */
        $relayState = '';
        $algorithm = '';
        $body = '';
        foreach(explode('&', $request->getUri()->getQuery()) as $e) {
            $tmp = explode('=', $e, 2);
            $name = $tmp[0];
            $value = count($tmp) === 2 ? $tmp[1] : '';
            $name = urldecode($name);
            switch($name) {
                case HttpMessageInterface::PARAM_SAML_REQUEST:
                case HttpMessageInterface::PARAM_SAML_RESPONSE:
                    $body = $name . '=' . $value;
                    break;
                case HttpMessageInterface::PARAM_SAML_RELAYSTATE:
                    $relayState = '&RelayState=' . $value;
                    break;
                case HttpMessageInterface::PARAM_SAML_SIGALG:
                    $algorithm = '&SigAlg=' . $value;
                    break;
            }
        }
        $signature = $body . $relayState . $algorithm;

        // verify signature
        $algo = $request->getParam(HttpMessageInterface::PARAM_SAML_SIGALG);
        try {
            $key = new XMLSecurityKey($algo ?? XMLSecurityKey::RSA_SHA1, ['type' => 'public']);
            $key->loadKey($certificate->toString());
        } catch (Exception $e) {
            throw new SamlCannotLoadCryptoKeyException($certificate, $e->getMessage());
        }
        $result = $key->verifySignature($signature, $requestSignature->toString());
        return (is_bool($result) && $result === true) || $result === 1;
    }
}
