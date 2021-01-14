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
namespace modethirteen\AuthForge\ServiceProvider;

use modethirteen\AuthForge\Common\Http\ServerRequestEx;
use modethirteen\Http\XUri;

interface AuthFlowServiceInterface {

    // value added to the current time in time condition validations
    const ALLOWED_CLOCK_DRIFT = 180;

    /**
     * @param ServerRequestEx $request
     * @return XUri
     */
    public function getAuthenticatedUri(ServerRequestEx $request) : XUri;

    /**
     * @param XUri $returnUri
     * @return XUri
     */
    public function getLoginUri(XUri $returnUri) : XUri;

    /**
     * @param string $id - user identifier for downstream identity provider
     * @param XUri $returnUri
     * @return XUri|null
     */
    public function getLogoutUri(string $id, XUri $returnUri) : ?XUri;
}
