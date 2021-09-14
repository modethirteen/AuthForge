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
use modethirteen\AuthForge\Common\Http\Headers;
use modethirteen\AuthForge\ServiceProvider\OAuth\Exception\JsonWebKeysCachingCannotBuildJsonWebKeysResultException;
use modethirteen\FluentCache\CacheBuilder;
use modethirteen\Http\Result;
use modethirteen\Http\XUri;
use modethirteen\TypeEx\StringEx;
use Psr\SimpleCache\CacheInterface;

class JsonWebKeySetCaching implements JsonWebKeySetCachingInterface {
    const DEFAULT_TTL = 86400;

    /**
     * @var CacheInterface
     */
    private CacheInterface $cache;

    /**
     * @var Closure
     */
    private Closure $cacheKeyBuilder;

    /**
     * @param CacheInterface $cache
     * @param Closure $cacheKeyBuilder - <$cacheKeyBuilder(XUri $jsonWebKeySetUri) : ?string>
     */
    public function __construct(CacheInterface $cache, Closure $cacheKeyBuilder) {
        $this->cache = $cache;
        $this->cacheKeyBuilder = $cacheKeyBuilder;
    }

    public function getJsonWebKeySetResult(XUri $jsonWebKeySetUri, bool $ignoreCachedResult, Closure $builder) : Result {
        $builder = (new CacheBuilder())
            ->withBuilder(function() use ($builder) : Result {
                $result = $builder();
                if(!($result instanceof Result)) {
                    throw new JsonWebKeysCachingCannotBuildJsonWebKeysResultException();
                }
                return $result;
            })
            ->withBuildValidator(function(Result $result) : bool {
                return $result->isSuccess();
            });
        $cacheKey = $this->newCacheKey($jsonWebKeySetUri);
        if($cacheKey !== null) {
            $builder = $builder->withCache($this->cache, function() use ($cacheKey) {
                return $cacheKey;
            })
            ->withCacheValidator(function($result) use ($jsonWebKeySetUri, $ignoreCachedResult) : bool {
                if($ignoreCachedResult) {
                    return false;
                }
                if($result instanceof Result) {
                    return true;
                }

                // cached object is not a JWKS HTTP result - generate a new cache key in case any dependencies have changed
                if($result !== null) {
                    $this->cache->delete($this->newCacheKey($jsonWebKeySetUri));
                }
                return false;
            })
            ->withCacheLifespanBuilder(function(Result $result) : int {
                $ttl = self::DEFAULT_TTL;
                $cacheControl = $result->getHeaders()->getHeaderLine(Headers::HEADER_CACHE_CONTROL);
                if(!StringEx::isNullOrEmpty($cacheControl)) {
                    $matches = [];

                    // assume `cache-control: must-revalidate`: it's the most aggressive revalidation with the remote
                    // source, and necessary since we are dealing with signature verification keys
                    if(preg_match('/max-age=(\d+)\b/', $cacheControl, $matches)) {
                        if(isset($matches[1])) {
                            $ttl = intval($matches[1]);
                        }
                    }
                }
                return $ttl;
            });
        }
        return $builder->get();
    }

    /**
     * @param XUri $jsonWebKeysUri
     * @return string
     */
    private function newCacheKey(XUri $jsonWebKeysUri) : ?string {
        $func = $this->cacheKeyBuilder;
        return $func($jsonWebKeysUri);
    }
}
