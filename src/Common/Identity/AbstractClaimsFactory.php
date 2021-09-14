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
namespace modethirteen\AuthForge\Common\Identity;

use Psr\Log\LoggerInterface;

abstract class AbstractClaimsFactory {

    /**
     * @var string[]
     */
    private array $allowedClaims;

    /**
     * @var LoggerInterface
     */
    private LoggerInterface $logger;

    /**
     * @param string[] $allowedClaims - string list of allowed claim names
     * @param LoggerInterface $logger
     */
    public function __construct(LoggerInterface $logger, array $allowedClaims = []) {
        $this->logger = $logger;
        $this->allowedClaims = $allowedClaims;
    }

    /**
     * @param array<string, mixed> $data - <claim name, value> authentication and identity data from identity provider
     * @return array
     */
    protected function getFilteredClaimsData(array $data) : array {
        $filteredClaimsData = array_filter($data, function($name) : bool {
            return in_array($name, $this->allowedClaims);
        }, ARRAY_FILTER_USE_KEY);
        $this->logger->debug('Removing claims not explicitly allowed...', [
            'RemovedClaims' => array_values(array_diff(array_keys($data), array_keys($filteredClaimsData)))
        ]);
        return $filteredClaimsData;
    }

    /**
     * @return LoggerInterface
     */
    protected function getLogger() : LoggerInterface {
        return $this->logger;
    }
}
