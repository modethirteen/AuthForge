<?php
/** @noinspection DuplicatedCode */
declare(strict_types=1);
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
namespace modethirteen\AuthForge\Tests\ServiceProvider\OAuth\JsonWebTokenClaims;

use modethirteen\AuthForge\ServiceProvider\OAuth\JsonWebTokenClaims;
use modethirteen\AuthForge\Tests\ServiceProvider\OAuth\AbstractOAuthTestCase;
use modethirteen\TypeEx\Exception\InvalidDictionaryValueException;

class toArray_Test extends AbstractOAuthTestCase {

    /**
     * @test
     * @throws InvalidDictionaryValueException
     */
    public function Can_return_array() : void {

        // arrange
        $claims = new JsonWebTokenClaims();
        $claims->set('iat', 1531406335);
        $claims->set('nbf', 1531406335);
        $claims->set('exp', 1531409935);
        $claims->set('iss', 'plugh');
        $claims->set('aud', '0oafuv29cxTJWpZng0h7');
        $claims->set('sub', 'modethirteen');
        $claims->set('first_name', 'jack');
        $claims->set('last_name', 'fubar');
        $claims->set('groups', ['a', 'b', 'c']);
        $claims->set('quuv', 'qux');
        $claims->set('fubar', 'fff');

        // act
        $result = $claims->toArray();

        // assert
        static::assertEquals([
            'iat' => 1531406335,
            'nbf' => 1531406335,
            'exp' => 1531409935,
            'iss' => 'plugh',
            'aud' => '0oafuv29cxTJWpZng0h7',
            'sub' => 'modethirteen',
            'first_name' => 'jack',
            'last_name' => 'fubar',
            'groups' => ['a', 'b', 'c'],
            'quuv' => 'qux',
            'fubar' => 'fff'
        ], $result);
    }
}
