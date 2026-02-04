<?php

declare(strict_types=1);

use League\OAuth2\Client\OptionProvider\OptionProviderInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\GenericProvider;
use setasign\SetaPDF2\Signer\Digest;
use setasign\SetaPDF\Signer\Module\CSC\Client;
use setasign\SetaPDF\Signer\Module\CSC\Module;
use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Reader\FileReader;
use setasign\SetaPDF2\Core\Writer\FileWriter;
use setasign\SetaPDF2\Core\Writer\StringWriter;
use setasign\SetaPDF2\Core\Writer\TempFileWriter;
use setasign\SetaPDF2\Signer\DocumentSecurityStore;
use setasign\SetaPDF2\Signer\Signature\Module\Pades;
use setasign\SetaPDF2\Signer\Signer;
use setasign\SetaPDF2\Signer\TmpDocument;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\Collector;
use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Signer\X509\Collection;

require_once(__DIR__ . '/../vendor/autoload.php');

/**
 * This file uses league/oauth2-client (https://github.com/thephpleague/oauth2-client) as oauth implementation.
 */

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
$requestFactory = new Http\Factory\Guzzle\RequestFactory();
$streamFactory = new Http\Factory\Guzzle\StreamFactory();
$client = new Client($apiUri, $httpClient, $requestFactory, $streamFactory);

$oauth2Urls = $client->getOauth2Info();
$provider = new GenericProvider([
    'clientId' => $settings['clientId'],
    'clientSecret' => $settings['clientSecret'],
    'redirectUri' => rtrim($settings['demoUrl'], '/') . '/async-demo.php?action=sign',
    'urlAuthorize' => $oauth2Urls['urlAuthorize'],
    'urlAccessToken' => $oauth2Urls['urlAccessToken'],
    'urlResourceOwnerDetails' => $oauth2Urls['urlResourceOwnerDetails'],
] /*
 // If your OAuth endpoint requires a JSON document instead of a form-encoded document pass following "optionProvider"
 // to the GenericProvider constructor:
 , [
    'optionProvider' => new class implements OptionProviderInterface {
        public function getAccessTokenOptions($method, array $params)
        {
            $options = ['headers' => ['content-type' => 'application/json']];

            if ($method === AbstractProvider::METHOD_POST) {
                $options['body'] = json_encode($params);
            }

            return $options;
        }
    }
]*/);

$action = $_GET['action'] ?? 'preview';
// if the oauth request was unsuccessful, return to preSign
if ($action === 'sign' && isset($_GET['error'])) {
    $action = 'preview';
}

switch ($action) {
    case 'preview':
        echo '<iframe src="?action=previewDocument" style="width: 90%; height: 90%;"></iframe><br/><br/>'
            . '<div style="text-align: right;"><a href="?action=preSign" style="background-color: #4CAF50; border: none; color: white; padding: 15px 32px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px; border-radius: 8px;">Sign</a></div>';
        break;

    case 'previewDocument':
        header('Content-Type: application/pdf');
        header('Content-Disposition: inline; filename="' . basename($fileToSign, '.pdf') . '.pdf"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
        header('Pragma: public');
        $data = file_get_contents($fileToSign);
        header('Content-Length: ' . strlen($data));
        echo $data;
        flush();
        break;

    case 'preSign':
        $credentialIds = ($client->credentialsList($accessToken))['credentialIDs'];
        // we just use the first credential on the list
        $credentialId = $credentialIds[0];

        // fetch all information regarding your credential id like the certificates
        $credentialInfo = $client->credentialsInfo($accessToken, $credentialId, 'chain', true, true);
        //    var_dump($credentialInfo);die();
        if ($credentialInfo['authMode'] !== 'oauth2code') {
            echo 'The selected credentialId does not support oauth2code authentification.'
                . ' A asynchronous sign request is not possible - take a look at the other demos instead.';
            die();
        }

        $certificates = $credentialInfo['cert']['certificates'];
        $certificates = array_map(static function (string $certificate) {
            return new Certificate($certificate);
        }, $certificates);
        // to cache the certificate files
        //foreach ($certificates as $k => $certificate) {
        //    file_put_contents('cert-' . $k . '.pem', $certificate->get());
        //}

        // the first certificate is always the signing certificate
        $certificate = array_shift($certificates);

        $signatureAlgorithmOid = $credentialInfo['key']['algo'][0];

        // create a writer instance
        $writer = new FileWriter($resultPath);
        // create the document instance
        $document = Document::loadByFilename($fileToSign, $writer);

        // create the signer instance
        $signer = new Signer($document);

        $module = new Pades();
        $module->setCertificate($certificate);
        $module->setExtraCertificates($certificates);

        ['hashAlgorithm' => $hashAlgorithm, 'signAlgorithm' => $signAlgorithm] = Module::findHashAndSignAlgorithm($signatureAlgorithmOid);
        $module->setDigest($hashAlgorithm);

        // create a collector instance
        $collector = new Collector(new Collection($certificates));
        // collect revocation information for this certificate
        $vriData = $collector->getByCertificate($certificate);

        foreach ($vriData->getOcspResponses() as $ocspResponse) {
            $module->addOcspResponse($ocspResponse);
        }
        foreach ($vriData->getCrls() as $crl) {
            $module->addCrl($crl);
        }

        $signer->setSignatureContentLength(20000);
        $tmpDocument = $signer->preSign(
            new FileWriter(TempFileWriter::createTempPath()),
            $module
        );
        if ($signAlgorithm === Digest::RSA_PSS_ALGORITHM) {
            $signatureAlgorithmParameters = Module::updateCmsForPssPadding($this->padesModule);
        }
        $hashData = base64_encode(hash($hashAlgorithm, $module->getDataToSign($tmpDocument->getHashFile()), true));

        $authorizationUrl = $provider->getAuthorizationUrl([
            'scope' => 'credential',
            'credentialID' => $credentialId,
            'hash' => $hashData
        ]);

        $_SESSION[__FILE__] = [
            'tmpDocument' => $tmpDocument,
            'hashData' => $hashData,
            'credentialID' => $credentialId,
            'module' => $module,
            'signAlgorithm' => $signAlgorithm,
            'signAlgorithmOid' => $signatureAlgorithmOid,
            'certificates' => $certificates,
            'vriData' => $vriData,
            'oauth2state' => $provider->getState(),
        ];

        header('Location: ' . $authorizationUrl);
        break;

    case 'sign':
        if (!isset($_SESSION[__FILE__]['hashData'])) {
            echo 'No session data found.<hr/>If you want to restart the signature process click here: <a href="?reset=1">Restart</a>';
            return;
        }

        // Check given state against previously stored one to mitigate CSRF attacks and replay attacks
        if ($_GET['state'] !== $_SESSION[__FILE__]['oauth2state']) {
            echo 'Invalid state<hr/>If you want to restart the signature process click here: <a href="?reset=1">Restart</a>';
            return;
        }

        $hashData = $_SESSION[__FILE__]['hashData'];

        /**
         * @var Pades $module
         */
        $module = $_SESSION[__FILE__]['module'];

        /**
         * @var TmpDocument $tmpDocument
         */
        $tmpDocument = $_SESSION[__FILE__]['tmpDocument'];

        $sad = $provider->getAccessToken('authorization_code', [
            'code' => $_GET['code']
        ]);

        $result = $client->signaturesSignHash(
            $accessToken,
            $_SESSION[__FILE__]['credentialID'],
            $sad->getToken(),
            [$hashData],
            $_SESSION[__FILE__]['signAlgorithmOid'],
            Digest::$oids[$module->getDigest()],
            isset($signatureAlgorithmParameters) ? (string)$signatureAlgorithmParameters : null
        );
//    var_dump($result);
        $signatureValue = (string) \base64_decode($result['signatures'][0]);
        if ($_SESSION[__FILE__]['signAlgorithm'] === Digest::ECDSA_ALGORITHM) {
            $signatureValue = Module::fixEccSignatures($signatureValue);
        }

        $module->setSignatureValue($signatureValue);

        // get the CMS structur from the signature module
        $cms = (string) $module->getCms();

        $reader = new FileReader($fileToSign);
        $tmpWriter = new TempFileWriter();

        $document = Document::load($reader, $tmpWriter);
        $signer = new Signer($document);

        $field = $signer->getSignatureField();
        $fieldName = $field->getQualifiedName();
        $signer->setSignatureFieldName($fieldName);

        $signer->saveSignature($tmpDocument, $cms);
        $document->finish();

        $writer = new StringWriter();
        $document = Document::loadByFilename($tmpWriter->getPath(), $writer);

        // create a VRI collector instance
        $collector = new Collector(new Collection($_SESSION[__FILE__]['certificates']));
        $vriData = $collector->getByFieldName(
            $document,
            $fieldName,
            Collector::SOURCE_OCSP_OR_CRL,
            null,
            null,
            $_SESSION[__FILE__]['vriData'] // pass the previously gathered VRI data
        );
        // and add it to the document.
        $dss = new DocumentSecurityStore($document);
        $dss->addValidationRelatedInfoByFieldName(
            $fieldName,
            $vriData->getCrls(),
            $vriData->getOcspResponses(),
            $vriData->getCertificates()
        );

        // save and finish the final document
        $document->save()->finish();

        $_SESSION[__FILE__] = [
            'pdf' => [
                'name' => 'signed.pdf',
                'data' => $writer->getBuffer()
            ]
        ];

        echo 'The file was successfully signed. You can download the result <a href="?action=download" download="signed.pdf" target="_blank">here</a>.<hr/>'
            . ' If you want to restart the signature process click here: <a href="?reset=1">Restart</a>';
        break;

    case 'download':
        $doc = $_SESSION[__FILE__]['pdf'];

        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="' . $doc['name']);
        header('Expires: 0');
        header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
        header('Pragma: public');
        header('Content-Length: ' . strlen($doc['data']));
        echo $doc['data'];
        flush();
        break;
}

