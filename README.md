# SetaPDF-Signer-Addon-CSC

This package offers a module for the SetaPDF-Signer component that allows you
to use an eSigner CSC conform API to digital sign PDF documents in pure PHP.

You can find the API documentation for CSC here:
https://cloudsignatureconsortium.org/wp-content/uploads/2020/01/CSC_API_V1_1.0.4.0.pdf

At the moment the module is only tested at ssl.com. We do not yet support all features or variances that may appear on 
other platforms. To test it yourself you can follow this article:
https://www.ssl.com/guide/integration-guide-testing-remote-signing-with-esigner-csc-api/

But instead of using postman you can use this module directly and sign your documents.

## Known not implemented features
At the moment we do not support RSA_PSS or ECDSA as signing algorithm because of missing testing options on our side.

Authentification is only supported over oauth2. Authentification over HTTP Basic or Digest
authentification is not supported yet. But an implementation of auth/login (11.2) should be 
relativly easy.t

Online One-Time Password (OTP) generation mechanism aren't supported yet. You'll have to trigger
the OTP generation by yourself - see API credentials/sendOTP (11.8).

## Requirements

To use this package you need access to an CSC API like [the eSigner from ssl.com](https://www.ssl.com/guide/integration-guide-testing-remote-signing-with-esigner-csc-api/).

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

This class communicates directly to your CSC API. It's constructor requires the following arguments:

- `$apiUri` The base url of your csc api e.g. "https://cs-try.ssl.com/csc/v0"
- `$httpClient` PSR-18 HTTP Client implementation.
- `$requestFactory` PSR-17 HTTP Factory implementation.
- `$streamFactory` PSR-17 HTTP Factory implementation.


### The `Module` class

This is the main signature module which can be used with the [SetaPDF-Signer](https://www.setasign.com/signer)
component. It's constructor requires the following arguments:

- `$accessToken` Your oauth access token
- `$client` Your client instance - see above 

### How do I get an access token?

You have to use an OAuth2 implementation like [league/oauth2-client](https://github.com/thephpleague/oauth2-client).
Sample code for this can be found in "[examples/generate-token.php](examples/generate-token.php)".

### Demo

A simple complete signature process would look like this:

```php
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
$credentialInfo = ($client->credentialsInfo($accessToken, [
    'credentialID' => $credentialId,
    'certificates' => 'chain',
    'authInfo' => true,
    'certInfo' => true
]));

$certificates = $credentialInfo['cert']['certificates'];
$certificates = array_map(function (string $certificate) {
    return new SetaPDF_Signer_X509_Certificate($certificate);
}, $certificates);

foreach ($certificates as $k => $certificate) {
    file_put_contents('cert-' . $k . '.pem', $certificate->get());
}

// the first certificate is always the signing certificate
$certificate = array_shift($certificates);
$algorithm = $credentialInfo['key']['algo'][0];

$module = new setasign\SetaPDF\Signer\Module\CSC\Module(
    $accessToken,
    $client
);
$module->setSignatureAlgorithmOid($algorithm);
$module->setCertificate($certificate);

if (isset($_GET['otp'])) {
    $module->setOtp($_GET['otp']);
}
if (isset($_GET['pin'])) {
    $module->setPin($_GET['pin']);
}

// the file to sign
$fileToSign = __DIR__ . '/Laboratory-Report.pdf';

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