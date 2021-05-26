# SetaPDF-Signer-Addon-CSC

This package offers a module for the SetaPDF-Signer component that allows you to use the
[Cloud Signature Consortium](https://cloudsignatureconsortium.org) API for Remote Electronic Signatures and Remote 
Electronic Seals to digital sign PDF documents in pure PHP.

The API documentation can be found on the Cloud Signature Consortium website:
https://cloudsignatureconsortium.org/resources/download-api-specifications/

At writing time the module is tested with the eSigner CSC API from SSL.com. 
It currently does not support all features or variances that may appear in other API implementations.
You can follow this integration guide to get a better understanding of how to setup a test environment and how the
signature workflow works: 
https://www.ssl.com/guide/integration-guide-testing-remote-signing-with-esigner-csc-api/

We implemented the same workflow in this module but instead of using postman you can use the module directly and 
sign your PDF documents locally.

## Known not implemented features

At the moment the module does not support RSA_PSS or ECDSA as signing algorithm because of missing testing options.
Both are implemented but will throw an exception to get a chance for a test case. Please contact us at
support@setasign.com so that we can work on a final implementation together.

Authentification is only supported over [OAuth2](https://oauth.net/2/). Authentification over HTTP Basic or Digest
authentification is not implemented yet. An implementation of the `auth/login` (11.2) endpoint shouldn't require much 
efford. If you need this, feel free to contact us at support@setasign.com so that we can work on this together.

Online One-Time Password (OTP) generation mechanism is not implemented yet. You'll have to trigger
the OTP generation by yourself - see API `credentials/sendOTP` (11.8).

## Requirements

To use this package you need access to a CSC API.

This package is developed and tested on PHP >= 7.1. Requirements of the 
[SetaPDF-Signer](https://www.setasign.com/signer)
component can be found [here](https://manuals.setasign.com/setapdf-signer-manual/getting-started/#index-1).

We're using [PSR-17 (HTTP Factories)](https://www.php-fig.org/psr/psr-17/) and 
[PSR-18 (HTTP Client)](https://www.php-fig.org/psr/psr-18/) for the requests. So you'll need an implementation of 
these. We recommend using Guzzle.

### For PHP 7.1
```
    "require" : {
        "guzzlehttp/guzzle": "^6.5",
        "http-interop/http-factory-guzzle": "^1.0",
        "mjelamanov/psr18-guzzle": "^1.3"
    }
```

### For >= PHP 7.2
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
        "setasign/setapdf-signer-addon-csc": "dev-master"
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

### The `Module` class

This is the main signature module which can be used with the [SetaPDF-Signer](https://www.setasign.com/signer)
component. It's constructor requires the following arguments:

- `$accessToken` The access token
- `$client` A `Client` instance - see above 

### How do I get an access token?

An access token is returned by an authorization to the API service. 

This was tested only by an OAuth2 authorization yet. You can to use an OAuth2 implementation such as 
[league/oauth2-client](https://github.com/thephpleague/oauth2-client).
Sample code for this can be found in "[examples/generate-token.php](examples/generate-token.php)".

### Demo

A simple complete signature process would look like this:

```php
$accessToken = '...COMES E.G. FROM THE OAUTH2 AUTHORIZATION...';
$otp = '123456'; // one-time-password

$httpClient = new GuzzleHttp\Client();
// if you are using php 7.0 or 7.1
//$httpClient = new Mjelamanov\GuzzlePsr18\Client($httpClient);
$requestFactory = new Http\Factory\Guzzle\RequestFactory();
$streamFactory = new Http\Factory\Guzzle\StreamFactory();

$client = new Client($apiUri, $httpClient, $requestFactory, $streamFactory);

$credentialIds = ($client->credentialsList($accessToken)['credentialIds']);
// we just use the first credential on the list
$credentialId = $credentialIds[0];
// fetch all informations regarding your credential id like the certificates
$credentialInfo = $client->credentialsInfo($accessToken, $credentialId, 'chain', true, true);
// get the certificate chain
$certificates = $credentialInfo['cert']['certificates'];
// the first certificate is always the signing certificate
$certificate = array_shift($certificates);
$algorithm = $credentialInfo['key']['algo'][0];

$module = new setasign\SetaPDF\Signer\Module\CSC\Module(
    $accessToken,
    $client
);
$module->setSignatureAlgorithmOid($algorithm);
$module->setCertificate($certificate);
$module->setExtraCertificates($certificates);
$module->setOtp($otp);

// the file to sign
$fileToSign = __DIR__ . '/assets/Laboratory-Report.pdf';

// create a writer instance
$writer = new SetaPDF_Core_Writer_File('signed.pdf');
// create the document instance
$document = SetaPDF_Core_Document::loadByFilename($fileToSign, $writer);

// create the signer instance
$signer = new SetaPDF_Signer($document);
$signer->sign($module);
```

## License

This package is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
