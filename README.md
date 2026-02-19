# SetaPDF-Signer-Addon-CSC

This package offers a module for the SetaPDF-Signer component that allows you to use the
[Cloud Signature Consortium](https://cloudsignatureconsortium.org) API for Remote Electronic Signatures and Remote 
Electronic Seals to digital sign PDF documents in pure PHP.

The API documentation can be found on the Cloud Signature Consortium website:
https://cloudsignatureconsortium.org/resources/download-api-specifications/

At the time of writing the module is tested with the eSigner CSC API from [SSL.com](https://www.ssl.com/esigner/) (v0), the Remote Signing Service 
CSC API from Entrust (v0) and CSC API from the [A-Trust Hash-Signing](https://www.a-trust.at/de/produkte/signaturl%C3%B6sungen_f%C3%BCr_unternehmen/hash-signing_csc/) (v1).
It currently does not support all features or variances that may appear in other API implementations.

For usage with SSL.com you can follow this integration guide to get a better understanding of how to setup a test 
environment and how the signature workflow works: 
https://www.ssl.com/guide/integration-guide-testing-remote-signing-with-esigner-csc-api/
(instead of using postman you can use this module directly and sign your PDF documents locally).

## Known not implemented features

At the moment the module does not support RSA_PSS as signing algorithm because of missing testing options.
The current implementation but will throw an exception to get a chance for a test case. Please contact us at
support@setasign.com so that we can work on a final implementation together.

Authentification is only supported over [OAuth2](https://oauth.net/2/). Authentification over HTTP Basic or Digest
authentification is not implemented yet. An implementation of the `auth/login` (11.2) endpoint shouldn't require much 
efford. If you need this, feel free to contact us at support@setasign.com so that we can work on this together.

Online One-Time Password (OTP) generation mechanism is not implemented yet. You'll have to trigger
the OTP generation by yourself - see API `credentials/sendOTP` (11.8).

## Requirements

To use this package you need access to a CSC API (v0 or v1).

This package is developed and tested on PHP >= 7.3 up to PHP 8.5. Requirements of the 
[SetaPDF-Signer](https://www.setasign.com/signer)
component can be found [here](https://manuals.setasign.com/setapdf-signer-manual/getting-started/#index-1).

We're using [PSR-17 (HTTP Factories)](https://www.php-fig.org/psr/psr-17/) and 
[PSR-18 (HTTP Client)](https://www.php-fig.org/psr/psr-18/) for the requests. So you'll need an implementation of 
these. We recommend using Guzzle:

```
    "require" : {
        "guzzlehttp/guzzle": "^7.0",
        "http-interop/http-factory-guzzle": "^1.0"
    }
```

## Installation
Add following to your composer.json:

```json
{
    "require": {
        "setasign/setapdf-signer-addon-csc": "^1.2"
    },
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

and execute `composer update`. You need to define the `repository` to resolve the dependency to the
[SetaPDF-Signer](https://www.setasign.com/signer) component
(see [here](https://getcomposer.org/doc/faqs/why-can%27t-composer-load-repositories-recursively.md) for more details).


## Usage

All classes in this package are located in the namespace `setasign\SetaPDF\Signer\Module\CSC`.

### The `Client` class

This class is a kind of proxy class to the CSC API. Its constructor requires the following arguments:

- `$apiUri` The base url of your csc api e.g. `https://cs-try.ssl.com/csc/v0`
- `$httpClient` PSR-18 HTTP Client implementation.
- `$requestFactory` PSR-17 HTTP Factory implementation.
- `$streamFactory` PSR-17 HTTP Factory implementation.

If you need to call an endpoint which is not covered by a proxy method, you can use the `call(string $path, ?string $accessToken = null, array $inputData = [])` method.

### How do I get an access token?

An access token is returned by an authorization to the API service.

This was tested only by an OAuth2 authorization yet. You can to use an OAuth2 implementation such as
[league/oauth2-client](https://github.com/thephpleague/oauth2-client).
Sample code for this can be found in "[examples/generate-token.php](examples/generate-token.php)".

### Authorization modes

Accessing a credential for remote signing requires an authorization from the user who owns it to control the signing
key associated to it. 

The CSC API supports multiple authorization modes. The authorization mode also defines whether the signing process must
be asynchronous or not. To get this information you can call `Client::credentialsInfo()` and in the key "authMode" you'll
find one of the following authorization modes:

- implicit: the authorization process is managed by the remote service autonomously. Authentication factors are managed by the remote signing service provider by interacting directly with the user, and not by the signature application.
- explicit: the authorization process is managed by the signature application, which collects authentication factors like PIN or One-Time Passwords (OTP).
- oauth2code: the authorization process is managed by the remote service using an OAuth 2.0 mechanism based on authorization code.

For both "implicit" and "explicit" you can use the synchronous process (see [examples/demo.php](examples/demo.php) and [examples/ltv-demo.php](examples/ltv-demo.php)).

For "oauth2code" you must use the asynchronous process (see [examples/demo-async.php](examples/async-demo.php)). This 
will require an oauth2 implementation such as
[league/oauth2-client](https://github.com/thephpleague/oauth2-client).

More about the authorization modes can be found in "8.2 Credential authorization" of the CSC API.

## License

This package is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
