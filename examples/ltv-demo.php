<?php

declare(strict_types=1);

use setasign\SetaPDF\Signer\Module\CSC\Client;
use setasign\SetaPDF\Signer\Module\CSC\ClientException;
use setasign\SetaPDF\Signer\Module\CSC\Module;

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

require_once(__DIR__ . '/../vendor/autoload.php');

session_start();

if (!file_exists('settings.php')) {
    echo 'The settings.php file is missing. See settings.php.dist for an example.';
    die();
}

$settings = require 'settings.php';
$apiUri = $settings['apiUri'];

$fileToSign = __DIR__ . '/assets/Laboratory-Report.pdf';
$resultPath = 'signed.pdf';

$timestampingUrl = 'http://ts.ssl.com';
$trustedCertificatesPath = __DIR__ . '/assets/SSL.com.ca-bundle';
$otherTrustedCertificatePaths = [__DIR__ . '/assets/SSL.com.dev-ca.cer'];

// to create or update your access token you have to call generate-token.php first
if (!isset($_SESSION['accessToken']['access_token'])) {
    echo 'Missing access token! <a href="generate-token.php">Login here</a>';
    die();
}
// check if the access token is still valid
if (!isset($_SESSION['accessToken']['expires']) || $_SESSION['accessToken']['expires'] < time()) {
    echo 'Access token is expired! <a href="generate-token.php">Renew here</a>';
    die();
}
$accessToken = $_SESSION['accessToken']['access_token'];

$httpClient = new GuzzleHttp\Client();
$httpClient = new Mjelamanov\GuzzlePsr18\Client($httpClient);
$requestFactory = new Http\Factory\Guzzle\RequestFactory();
$streamFactory = new Http\Factory\Guzzle\StreamFactory();
$client = new Client($apiUri, $httpClient, $requestFactory, $streamFactory);

echo '<pre>';
$credentialIds = ($client->credentialsList($accessToken)['credentialIDs']);
var_dump($credentialIds);
// we just use the first credential on the list
$credentialId = $credentialIds[0];
// fetch all information regarding your credential id like the certificates
$credentialInfo = $client->credentialsInfo($accessToken, $credentialId, 'chain', true, true);
var_dump($credentialInfo);
echo '</pre>';

// INFO: YOU SHOULD CACHE THE DATA IN $credentialInfo FOR LESS API REQUESTS

if ($credentialInfo['authMode'] === 'oauth2code') {
    echo 'The selected credentialId does only support oauth2code authentification.'
        . ' A synchronous sign request is not possible - take a look at the <a href="async-demo.php">async-demo</a> instead.';
    die();
}

$certificates = $credentialInfo['cert']['certificates'];
$certificates = array_map(function (string $certificate) {
    return new SetaPDF_Signer_X509_Certificate($certificate);
}, $certificates);

$certificate = array_shift($certificates);
$algorithm = $credentialInfo['key']['algo'][0];

$module = new Module($accessToken, $client);
$module->setCredentialId($credentialId);
$module->setSignatureAlgorithmOid($algorithm);
$module->setCertificate($certificate);

// now add this information to the CMS container
$module->setExtraCertificates($certificates);

// create a collection of trusted certificats:
$trustedCertificates = new SetaPDF_Signer_X509_Collection($certificates[count($certificates) - 1]);
$trustedCertificates->add(SetaPDF_Signer_Pem::extractFromFile($trustedCertificatesPath));
// sadly not all CSC API implementations return the full chain (in our tests e.g. SSL.com), so we have to
// add a trusted root on our own:
foreach ($otherTrustedCertificatePaths as $otherTrustedCertificatePath) {
    $trustedCertificates->addFromFile($otherTrustedCertificatePath);
}

// create a collector instance
$collector = new SetaPDF_Signer_ValidationRelatedInfo_Collector($trustedCertificates);
$vriData = $collector->getByCertificate($certificate);
foreach ($vriData->getOcspResponses() as $ocspResponse) {
    $module->addOcspResponse($ocspResponse);
}
foreach ($vriData->getCrls() as $crl) {
    $module->addCrl($crl);
}

if ($credentialInfo['authMode'] === 'explicit' && !isset($_GET['otp']) && !isset($_GET['pin'])) {
    // you should check the OTP and/or PIN entry in $credentialInfo for how to setup authentication exactly
    echo 'Please enter OTP or PIN:';
    echo '<form><input type="text" name="otp" placeholder="OTP"> or <input type="text" name="pin" placeholder="PIN">';
    echo '<input type="submit"/></form>';
    die();
}

if (isset($_GET['otp'])) {
    $module->setOtp($_GET['otp']);
}
if (isset($_GET['pin'])) {
    $module->setPin($_GET['pin']);
}

// create a writer instance
$writer = new SetaPDF_Core_Writer_File($resultPath);
$tmpWriter = new SetaPDF_Core_Writer_TempFile();
// create the document instance
$document = SetaPDF_Core_Document::loadByFilename($fileToSign, $tmpWriter);

// create the signer instance
$signer = new SetaPDF_Signer($document);
// because of the timestamp and VRI data we need more space for the signature container
$signer->setSignatureContentLength(40000);

// setup a timestamp module
$tsModule = new SetaPDF_Signer_Timestamp_Module_Rfc3161_Curl($timestampingUrl);
$signer->setTimestampModule($tsModule);

// add a signature field manually to get access to its name
$signatureField = $signer->addSignatureField();
// ...this is needed to add validation related information later
$signer->setSignatureFieldName($signatureField->getQualifiedName());

try {
    $signer->sign($module);
} catch (ClientException $e) {
    echo 'An error occured:';
    echo $e->getMessage() . ': ' . $e->getResponse()->getBody();
    echo '<br/><a href="?">restart</a>';
    die();
} catch (\Exception $e) {
    echo 'An error occured:';
    echo $e->getMessage();
    echo '<br/><a href="?">restart</a>';
    die();
}

// create a new instance
$document = SetaPDF_Core_Document::loadByFilename($tmpWriter->getPath(), $writer);

// create a VRI collector instance
$collector = new SetaPDF_Signer_ValidationRelatedInfo_Collector($trustedCertificates);
// Use IPv4 to bypass an issue at http://ocsp.ensuredca.com
//$collector->getOcspClient()->setCurlOption([
//    CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4
//]);

// get VRI for the timestamp signature
$vriData = $collector->getByFieldName(
    $document,
    $signatureField->getQualifiedName(),
    SetaPDF_Signer_ValidationRelatedInfo_Collector::SOURCE_OCSP_OR_CRL,
    null,
    null,
    $vriData // pass the previously gathered VRI data
);

//$logger = $collector->getLogger();
//foreach ($logger->getLogs() as $log) {
//    echo str_repeat(' ', $log->getDepth() * 4) . $log . "\n";
//}

// and add it to the document.
$dss = new SetaPDF_Signer_DocumentSecurityStore($document);
$dss->addValidationRelatedInfoByFieldName(
    $signatureField->getQualifiedName(),
    $vriData->getCrls(),
    $vriData->getOcspResponses(),
    $vriData->getCertificates()
);

// save and finish the final document
$document->save()->finish();

echo '<a href="data:application/pdf;base64,' . base64_encode(file_get_contents($resultPath)) . '" ' .
    'download="' . basename($resultPath) . '">download</a> | <a href="?">restart</a><br />';
