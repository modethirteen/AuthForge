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
namespace modethirteen\AuthForge\Common\Http;

use Closure;
use modethirteen\AuthForge\Common\Exception\ServerRequestInterfaceParsedBodyException;
use modethirteen\Http\Exception\MalformedUriException;
use modethirteen\Http\IQueryParams;
use modethirteen\Http\QueryParams;
use modethirteen\Http\XUri;
use modethirteen\TypeEx\StringEx;
use modethirteen\XArray\XArray;
use Psr\Http\Message\ServerRequestInterface;

class ServerRequestEx {

    /**
     * @var XArray|null
     */
    private ?XArray $body = null;

    /**
     * @var Closure
     */
    private Closure $bodyParser;

    /**
     * @var ServerRequestInterface
     */
    private ServerRequestInterface $instance;

    /**
     * @note ServerRequestInterface doesn't really help us understand if this is a application/x-www-form-urlencoded body, so a callback will ensure it is serialized to an array type
     * @param ServerRequestInterface $instance
     * @param Closure $bodyParser - <$bodyParser(ServerRequestInterface $instance) : array>
     */
    public function __construct(ServerRequestInterface $instance, Closure $bodyParser) {
        $this->instance = $instance;
        $this->bodyParser = $bodyParser;
    }

    /**
     * @return XArray
     * @throws ServerRequestInterfaceParsedBodyException
     */
    public function getBody() : XArray {
        if($this->body === null) {
            $func = $this->bodyParser;
            $result = $func($this->instance);
            if(!is_array($result)) {
                throw new ServerRequestInterfaceParsedBodyException($result);
            }
            $this->body = new XArray($result);
        }
        return $this->body;
    }

    /**
     * Look for parameter in POST content body then fallback to query parameters
     *
     * @param string $param
     * @return string|null
     * @throws ServerRequestInterfaceParsedBodyException
     */
    public function getParam(string $param) : ?string {
        if($this->isPost()) {
            $result = $this->getBody()->getVal($param);
            if($result !== null) {
                return StringEx::stringify($result);
            }
        }
        return $this->getQueryParams()->get($param);
    }

    /**
     * @return IQueryParams
     */
    public function getQueryParams() : IQueryParams {
        return QueryParams::newFromArray($this->instance->getQueryParams());
    }

    /**
     * @return XUri
     * @throws MalformedUriException
     */
    public function getUri() : XUri {
        return XUri::newFromString(StringEx::stringify($this->instance->getUri()));
    }

    /**
     * @return bool
     */
    public function isPost() : bool {
        return (new StringEx(
            StringEx::stringify($this->instance->getMethod())
        ))->equalsInvariantCase('POST');
    }
}