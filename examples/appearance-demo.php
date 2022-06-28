<?php

declare(strict_types=1);

use setasign\SetaPDF\Signer\Module\CSC\Client;
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
$credentialIds = ($client->credentialsList($accessToken))['credentialIDs'];
var_dump($credentialIds);
// we just use the first credential on the list
$credentialId = $credentialIds[0];
// fetch all information regarding your credential id like the certificates
$credentialInfo = $client->credentialsInfo($accessToken, $credentialId, 'chain', true, true);
var_dump($credentialInfo);
echo '</pre>';
if ($credentialInfo['authMode'] === 'oauth2code') {
    echo 'The selected credentialId does only support oauth2code authentification.'
        . ' A synchronous sign request is not possible - take a look at the <a href="async-demo.php">async-demo</a> instead.';
    die();
}

$certificates = $credentialInfo['cert']['certificates'];

// INFO: YOU SHOULD CACHE THE DATA IN $credentialInfo FOR LESS API REQUESTS

// the first certificate is always the signing certificate
$certificate = array_shift($certificates);
$algorithm = $credentialInfo['key']['algo'][0];

$module = new Module($accessToken, $client);
$module->setCredentialId($credentialId);
$module->setSignatureAlgorithmOid($algorithm);
$module->setCertificate($certificate);
$module->setExtraCertificates($certificates);

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
// create the document instance
$document = SetaPDF_Core_Document::loadByFilename($fileToSign, $writer);

// create the signer instance
$signer = new SetaPDF_Signer($document);

$field = $signer->addSignatureField(
    'Signature',
    1,
    SetaPDF_Signer_SignatureField::POSITION_RIGHT_TOP,
    ['x' => -160, 'y' => -100],
    180,
    60
);

$signer->setSignatureFieldName($field->getQualifiedName());

$appearance = new SetaPDF_Signer_Signature_Appearance_Dynamic($module);
$signer->setAppearance($appearance);

$signer->sign($module);

echo '<a href="data:application/pdf;base64,' . base64_encode(file_get_contents($resultPath)) . '" ' .
    'download="' . basename($resultPath) . '">download</a> | <a href="?">restart</a><br />';
