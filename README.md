# AuthForge

A collection of PHP components to integrate industry-standard authentication and authorization

[![github.com](https://github.com/modethirteen/AuthForge/workflows/build/badge.svg)](https://github.com/modethirteen/AuthForge/actions?query=workflow%3Abuild)
[![codecov.io](https://codecov.io/github/modethirteen/AuthForge/coverage.svg?branch=main)](https://codecov.io/github/modethirteen/AuthForge?branch=main)
[![Latest Stable Version](https://poser.pugx.org/modethirteen/authforge/version.svg)](https://packagist.org/packages/modethirteen/authforge)
[![Latest Unstable Version](https://poser.pugx.org/modethirteen/authforge/v/unstable)](https://packagist.org/packages/modethirteen/authforge)

* PHP 7.4 (main, 2.x)

## Installation

Use [Composer](https://getcomposer.org/). There are two ways to add this library to your project.

From the composer CLI:

```sh
./composer.phar require modethirteen/authforge
```

Or add modethirteen/authforge to your project's composer.json:

```json
{
    "require": {
        "modethirteen/authforge": "dev-main"
    }
}
```

`dev-main` is the main development branch. If you are using this library in a production environment, it is advised that you use a stable release.

Assuming you have setup Composer's autoloader, the library can be found in the `modethirteen\AuthForge\` namespace.

## Credits

Some components in this repository, specifically the signature, encryption, and verification of SAML SSO messages, are reworkings of libraries found in the  [OneLogin SAML PHP Toolkit](https://github.com/onelogin/php-saml). These components have been, and continue to be, refactored for flexibility and platform-agnostic, [PSR-compatible](https://www.php-fig.org/psr) programming.

## Getting Started

While it is possible to surgically use AuthForge components and libraries in your application, the quickest way to add SSO service provider capabilities to you application is to use the `AuthFlowServiceInterface`.

### OAuth 2.0 / OpenID Connect Service Provider (Relying Party)

```php
// the application is responsible for providing a concrete OAuth service provider configuration
// ...settings can come from anywhere: a file on disk, hardcoded strings, etc.
$oauth = new class implements OAuthConfigurationInterface { ... };

// ContextLoggerInterface is an extension of the PSR-3 LoggerInterface (https://www.php-fig.org/psr/psr-3/)
$logger = new class implements ContextLoggerInterface { ... };

// DateTimeInterface represents a consistent time of the authentication request or response
// ...this time will be used anywhere in the service where dates are outputted or timespans are checked
$dateTime = new DateTimeImmutable();

// a PSR-14 EventDispatcher is provided with a post-processing event from OAuthFlowService, so that the application can process identity token claims and natively sign-in or reject the authentication attempt
$eventDispatcher = new class implements EventDispatcherInterface { ... }

// a UUIDv4 generator for state tokens
$uuidFactory = new UuidFactory();

// MutableXArray (https://github.com/modethirteen/XArray) is a helper for writing data to an array data structure
// ...it is assumed that $_SESSION is provided to this object so proper state management can occur in OAuthFlowService
$session = new MutableXArray($_SESSION);

// a OAuthMiddlewareServiceInterface is responsible for handling any followup tasks with an OAuth 2.0 access token, such as, in the case of OpenID Connect, parse the identity token with the identity provider's JWKS, or fetch additional claims from an OpenID Connect UserInfo endpoint.

// ...time to configure our OAuthFlowService for OpenID Connect
$oidc = new class implements OpenIdConnectConfigurationInterface { ... }

// JWKS caching leverages a PSR-16 CacheInterface (https://www.php-fig.org/psr/psr-16/) to store remotely fetched identity token signing keys
$cache = new class implements CacheInterface { ... }
$caching = new JsonWebKeySetCaching($cache, function(XUri $jsonWebKeysUri) : string {

    // what cache key should be used to store JWKS in the cache? the configured remote URL is provided so the decision making is left to the application
    return 'key';
});

// ...create the OpenIdConnectMiddlewareService and include it in the OAuthFlowService
$middlewareService = new OpenIdConnectMiddlewareService($oauth, $oidc, $dateTime, $caching, $logger);
$service = new OAuthFlowService($oauth, $dateTime, $logger, $middlewareService, $eventDispatcher, $uuidFactory, $session);

// ...a NoopOauthMiddlewareService provides plain OAuth 2.0 with no followup tasks (just returns an OAuth 2.0 access token)
$middlewareService = new NoopOAuthMiddlewareService();

// the URI to return the user to after the sign-in flow is completed
$returnUri = XUri::newFromString('https://app.example.com/dashboard');

// ...back to OpenID Connect, time to kick-off an authorization code flow-based sign-in request to the identity provider and receive a URI to redirect the user to
$loginUri = $service->getLoginUri($returnUri);

// handle the redirect as the application sees fit
header("Location: {$loginUri->toString()}");
```

```text
HTTP 302 https://idp.example.com/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcode&response_type=code&state={state}&scope=openid
```

```php
// the application will handle request routing when the identity provider redirects the user back with an authorization code
// ...provide a PSR-7 ServiceRequestInterface and AuthForge will process the code, dispatch an post-processing event, and return the original application return URI
$request = new ServerRequestEx(new class implements ServerRequestInterface { ... }, function(ServerRequestInterface $req) {

    // PSR-7 messages are not strictly opinionated on the return type for the body (object|array|null)
    // ...AuthForge requires an array-type, therefore this callback needs to convert whatever the application HTTP message body type is to array
});
$returnUri = $service->getAuthenticatedUri($request);

// ...meanwhile what does the event dispatcher send off to its listeners?
$eventDispatcher->addListener(OAuthFlowEvent::class, function(object $event) : void {

    // time the service started processing the authorization code
    $event->getDateTime();

    // a collection of identity token claims
    $event->getClaims();

    // the OAuth middleware service that handled the flow (ex: OpenIdConnectMiddlewareService)
    $event->getMiddlewareServiceName();

    // the raw HTTP response from requesting an access token from the identity provider
    $event->getTokenResult();
});

// the application should now have everything it needs to sign in the user (or not!)
```

### SAML SSO Service Provider

```php
// the application is responsible for providing a concrete SAML SSO service provider configuration
// ...settings can come from anywhere: a file on disk, hardcoded strings, etc.
$oauth = new class implements SamlConfigurationInterface { ... };

// ContextLoggerInterface is an extension of the PSR-3 LoggerInterface (https://www.php-fig.org/psr/psr-3/)
$logger = new class implements ContextLoggerInterface { ... };

// DateTimeInterface represents a consistent time of the authentication request or response
// ...this time will be used anywhere in the service where dates are outputted or timespans are checked
$dateTime = new DateTimeImmutable();

// a PSR-14 EventDispatcher is provided with a post-processing event from SamlFlowService, so that the application can process identity token claims and natively sign-in or reject the authentication attempt
$eventDispatcher = new class implements EventDispatcherInterface { ... }

// a UUIDv4 generator for request IDs
$uuidFactory = new UuidFactory();

// the session index registry stores identity provider session indexes in whatever manner the application sees fit
// ...these session indexes are necessary to handle both SAML Single Logout service provider and identity provider initiated requests
$sessionIndexRegistry = new class implements SessionIndexRegistryInterface { ... }

// the document factory can parse, sign, and encrypt SAML
$documentFactory = new DocumentFactory(new class implements DocumentSchemaResolverInterface {

    /**
     * @param string $schema
     * @return string - a fully qualified OS path to the requested XSD file
     */
    public function resolve(string $schema) : string {

        // the SAML 2.0 schema definition files are located in this repository/package under /redist/OneLogin/schemas (thanks OneLogin!)
        // ...it's the responsibility of your application to correctly resolve a filesystem path to this directory
    }
});

// ...time to create the SamlFlowService
$service = new SamlFlowService($saml, $dateTime, $logger, $uuidFactory, $eventDispatcher, $documentFactory, $sessionIndexRegistry);

// the URI to return the user to after the sign-in flow is completed
$returnUri = XUri::newFromString('https://app.example.com/dashboard');

// generate an AuthnRequest to the identity provider and get a URI to redirect the user to
$loginUri = $service->getLoginUri($returnUri);

// handle the redirect as the application sees fit
header("Location: {$loginUri->toString()}");
```

```text
HTTP 302 https://idp.example.com/saml?SAMLRequest={request}&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature={signature}
```

```php
// the application will handle request routing when the identity provider redirects the user back with an AuthnResponse
// ...provide a PSR-7 ServiceRequestInterface and AuthForge will process the response, dispatch an post-processing event, and return the original application return URI
$request = new ServerRequestEx(new class implements ServerRequestInterface { ... }, function(ServerRequestInterface $req) {

    // PSR-7 messages are not strictly opinionated on the return type for the body (object|array|null)
    // ...AuthForge requires an array-type, therefore this callback needs to convert whatever the application HTTP message body type is to array
});
$returnUri = $service->getAuthenticatedUri($request);

// ...meanwhile what does the event dispatcher send off to its listeners?
$eventDispatcher->addListener(SamlFlowEvent::class, function(object $event) : void {

    // time the service started processing the AuthnResponse
    $event->getDateTime();

    // a collection of assertion attribute claims
    $event->getClaims();

    // the identity provider session index
    $event->getSessionIndex();
});

// the application should now have everything it needs to sign in the user (or not!)
```
