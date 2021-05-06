<?php

declare(strict_types=1);

use setasign\SetaPDF\Signer\Module\CSC\Module;

require_once(__DIR__ . '/../vendor/autoload.php');

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

session_start();

$settings = require 'settings.php';
$apiUri = $settings['apiUri'];

$fileToSign = __DIR__ . '/Laboratory-Report.pdf';
$resultPath = 'signed.pdf';

$timestampingUrl = 'http://timestamping.ensuredca.com';
$trustedCertificatesPath = __DIR__ . '/setapdf_demos@setasign_com.ca-bundle';


$httpClient = new GuzzleHttp\Client();
$httpClient = new Mjelamanov\GuzzlePsr18\Client($httpClient);
$requestFactory = new Http\Factory\Guzzle\RequestFactory();
$streamFactory = new Http\Factory\Guzzle\StreamFactory();

// to create or update your oauth access token you have to call generate-token.php first
if (!isset($_SESSION['accessToken']['access_token'])) {
    throw new RuntimeException('Missing access token!');
}
// validate the oauth access token
$accessToken = $_SESSION['accessToken']['access_token'];
if (isset($_SESSION['accessToken']['expires_in'])) {
    if (!is_numeric($_SESSION['accessToken']['expires_in'])) {
        throw new \InvalidArgumentException('expires_in value must be an integer');
    }

    $expires = $_SESSION['accessToken']['expires_in'] != 0 ? time() + $_SESSION['accessToken']['expires_in'] : 0;
} elseif (!empty($_SESSION['accessToken']['expires'])) {
    // Some providers supply the seconds until expiration rather than
    // the exact timestamp. Take a best guess at which we received.
    $expires = $_SESSION['accessToken']['expires'];

    // If the given value is larger than the original OAuth 2 draft date,
    // assume that it is meant to be a (possible expired) timestamp.
    $oauth2InceptionDate = 1349067600; // 2012-10-01
    if ($expires < $oauth2InceptionDate) {
        $expires += time();
    }
}

if (!isset($expires) || $expires <= time()) {
    throw new RuntimeException('Access token is expired!');
}

$module = new Module($accessToken, $apiUri, $httpClient, $requestFactory, $streamFactory);
$credentialIds = ($module->fetchCredentialsList());
var_dump($credentialIds);
$module->setCredentialId($credentialIds[0]);
$credential = ($module->fetchCredentialsInfo());
var_dump($credential);
$certificates = $credential['cert']['certificates'];
$certificates = array_map(function (string $certificate) {
    return new SetaPDF_Signer_X509_Certificate($certificate);
}, $certificates);
foreach ($certificates as $k => $certificate) {
    file_put_contents('cert-' . $k . '.pem', $certificate->get());
}

$certificate = array_shift($certificates);
$algorithm = $credential['key']['algo'][0];
$module->setSignatureAlgorithmOid($algorithm);
$module->setCertificate($certificate);


// now add these information to the CMS container
$module->setExtraCertificates($certificates);

// create a collection of trusted certificats:
$trustedCertificates = new SetaPDF_Signer_X509_Collection($certificates[count($certificates) - 1]);
$trustedCertificates->add(SetaPDF_Signer_Pem::extractFromFile($trustedCertificatesPath));

// create a collector instance
$collector = new SetaPDF_Signer_ValidationRelatedInfo_Collector($trustedCertificates);
$vriData = $collector->getByCertificate($certificate);
foreach ($vriData->getOcspResponses() as $ocspResponse) {
    $module->addOcspResponse($ocspResponse);
}
foreach ($vriData->getCrls() as $crl) {
    $module->addCrl($crl);
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

$signer->sign($module);

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
