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

use modethirteen\AuthForge\Common\Exception\ServerRequestInterfaceParsedBodyException;
use modethirteen\AuthForge\Common\Http\ServerRequestEx;
use modethirteen\AuthForge\ServiceProvider\Saml\Http\HttpMessageInterface;
use modethirteen\Http\Exception\MalformedPathQueryFragmentException;
use modethirteen\Http\Exception\MalformedUriException;
use modethirteen\Http\XUri;
use modethirteen\TypeEx\StringEx;
use Psr\Log\LoggerInterface;

trait RelayStateAuthFlowServiceTrait {

    /**
     * @param SamlConfigurationInterface $saml
     * @param ServerRequestEx $request
     * @param LoggerInterface $logger
     * @return XUri
     */
    protected function getRedirectUriFromRequestRelayState(SamlConfigurationInterface $saml, ServerRequestEx $request, LoggerInterface $logger) : XUri {
        try {
            $relayState = $request->getParam(HttpMessageInterface::PARAM_SAML_RELAYSTATE);
        } catch(ServerRequestInterfaceParsedBodyException $e) {
            $relayState = null;
            $this->logger->warning('Could not get the RelayState from the HTTP request, {{Error}}', [
                'Error' => $e->getMessage()
            ]);
        }
        if(!StringEx::isNullOrEmpty($relayState)) {
            $logger->debug('Found RelayState', ['RelayState' => $relayState]);
            try {
                return XUri::isAbsoluteUrl($relayState)
                    ? XUri::newFromString($relayState)
                    : $saml->getRelayStateBaseUri()->atPath($relayState);
            } catch(MalformedPathQueryFragmentException $e) {
                $this->logger->warning('Could not append relative RelayState to service provider base URI, {{Error}}', [
                    'Error' => $e->getMessage()
                ]);
            } catch(MalformedUriException $e) {
                $this->logger->warning('Could not parse absolute RelayState, {{Error}}', [
                    'Error' => $e->getMessage()
                ]);
            }
        }
        return $saml->getDefaultReturnUri();
    }
}
