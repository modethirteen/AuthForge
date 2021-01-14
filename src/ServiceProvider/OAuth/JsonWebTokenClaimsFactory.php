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
namespace modethirteen\AuthForge\ServiceProvider\OAuth;

use Closure;
use modethirteen\AuthForge\Common\Identity\AbstractClaimsFactory;
use modethirteen\AuthForge\Common\Identity\ClaimsFactoryInterface;
use modethirteen\AuthForge\Common\Identity\ClaimsInterface;
use modethirteen\TypeEx\Exception\InvalidDictionaryValueException;
use modethirteen\TypeEx\StringEx;

class JsonWebTokenClaimsFactory extends AbstractClaimsFactory implements ClaimsFactoryInterface {

    public function newClaims(array $data, ?Closure $validator = null) : ClaimsInterface {
        $filteredClaims = $this->getFilteredClaimsData($data);
        $instance = new JsonWebTokenClaims($validator);
        foreach($filteredClaims as $name => $value) {
            try {
                $instance->set(StringEx::stringify($name), $value);
            } catch (InvalidDictionaryValueException $e) {
                $this->getLogger()->warning('Could not process claim', [
                    'Claim' => $name,
                    'Error' => $e->getMessage()
                ]);
            }
        }
        return $instance;
    }
}
