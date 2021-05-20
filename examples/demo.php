<?php

declare(strict_types=1);

use setasign\SetaPDF\Signer\Module\CSC\Client;
use setasign\SetaPDF\Signer\Module\CSC\Module;

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

require_once(__DIR__ . '/../vendor/autoload.php');

session_start();

$settings = require 'settings.php';
$apiUri = $settings['apiUri'];

$fileToSign = __DIR__ . '/Laboratory-Report.pdf';
$resultPath = 'signed.pdf';

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

$credentialIds = ($client->credentialsList($accessToken))['credentialIDs'];
var_dump($credentialIds);
// we just use the first credential on the list
$credentialId = $credentialIds[0];
// fetch all informations regarding your credential id like the certificates
$credentialInfo = $client->credentialsInfo($accessToken, $credentialId, 'chain', true, true);
var_dump($credentialInfo);
$certificates = $credentialInfo['cert']['certificates'];
$certificates = array_map(function (string $certificate) {
    return new SetaPDF_Signer_X509_Certificate($certificate);
}, $certificates);
// to cache the certificate files
//foreach ($certificates as $k => $certificate) {
//    file_put_contents('cert-' . $k . '.pem', $certificate->get());
//}

// the first certificate is always the signing certificate
$certificate = array_shift($certificates);
$algorithm = $credentialInfo['key']['algo'][0];

$module = new Module($accessToken, $client);
$module->setCredentialId($credentialId);
$module->setSignatureAlgorithmOid($algorithm);
$module->setCertificate($certificate);
$module->setExtraCertificates($certificates);

if (isset($_GET['otp'])) {
    $module->setOtp($_GET['otp']);
}
if (isset($_GET['pin'])) {
    $module->setPin($_GET['pin']);
}

// create a writer instance
$writer = new SetaPDF_Core_Writer_File($resultPath);
// create the document instance
$document = SetaPDF_Core_Document::loadByFilename($fileToSign, $writer);

// create the signer instance
$signer = new SetaPDF_Signer($document);

$signer->sign($module);
