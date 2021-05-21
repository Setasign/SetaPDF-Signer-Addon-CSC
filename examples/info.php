<?php
/* A simple script, that calls the "info" method of the CSC API
 */
declare(strict_types=1);

use setasign\SetaPDF\Signer\Module\CSC\Client;

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

require_once(__DIR__ . '/../vendor/autoload.php');

$settings = require 'settings.php';
$apiUri = $settings['apiUri'];

$httpClient = new GuzzleHttp\Client();
$httpClient = new Mjelamanov\GuzzlePsr18\Client($httpClient);
$requestFactory = new Http\Factory\Guzzle\RequestFactory();
$streamFactory = new Http\Factory\Guzzle\StreamFactory();
$client = new Client($apiUri, $httpClient, $requestFactory, $streamFactory);

echo '<pre>';
var_dump($client->info());
echo '</pre>';
