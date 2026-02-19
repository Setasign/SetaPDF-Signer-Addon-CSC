<?php

use League\OAuth2\Client\OptionProvider\OptionProviderInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;
use setasign\SetaPDF\Signer\Module\CSC\Client;

require_once(__DIR__ . '/../vendor/autoload.php');

/**
 * This file uses league/oauth2-client (https://github.com/thephpleague/oauth2-client) as oauth implementation.
 */

$settings = require __DIR__ . '/settings.php';
$apiUri = $settings['apiUri'];

$httpClient = new GuzzleHttp\Client();
$requestFactory = new Http\Factory\Guzzle\RequestFactory();
$streamFactory = new Http\Factory\Guzzle\StreamFactory();

$client = new Client($apiUri, $httpClient, $requestFactory, $streamFactory);

$oauth2Urls = $client->getOauth2Info();
$provider = new GenericProvider([
    'clientId' => $settings['clientId'],
    'clientSecret' => $settings['clientSecret'],
    'redirectUri' => rtrim($settings['demoUrl'], '/') . '/generate-token.php',
    'urlAuthorize' => $oauth2Urls['urlAuthorize'],
    'urlAccessToken' => $oauth2Urls['urlAccessToken'],
    'urlResourceOwnerDetails' => $oauth2Urls['urlResourceOwnerDetails'],
]
/*
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
]*/
);

session_start();

if (isset($_GET['reset'])) {
    $_SESSION = [];
} elseif (isset($_SESSION['accessToken'])) {
    $accessToken = new AccessToken($_SESSION['accessToken']);
}

if (isset($_GET['error'])) {
    echo "<pre>";
    var_dump($_GET);
    echo "</pre>";
    die();
}

/** @noinspection PhpStatementHasEmptyBodyInspection */
if (isset($accessToken) && !$accessToken->hasExpired()) {
    // do nothing - the access token is still valid
} elseif (isset($accessToken) && $accessToken->getRefreshToken() !== null) {
    // access token has expired, but we have refresh token
    $accessToken = $provider->getAccessToken('refresh_token', [
        'refresh_token' => $accessToken->getRefreshToken()
    ]);

    $_SESSION['accessToken'] = $accessToken->jsonSerialize();
} else {
// If we don't have an authorization code then get one
    if (!isset($_GET['code'])) {
        // Fetch the authorization URL from the provider; this returns the
        // urlAuthorize option and generates and applies any necessary parameters
        // (e.g. state).
        $options = [
            'scope' => $settings['oauth2scope']
        ];

        if (isset($settings['accountId'])) {
            $options['account_token'] = $client->createAccountToken(
                $settings['accountId'],
                $settings['clientId'],
                $settings['clientSecret']
            );
        }

        $authorizationUrl = $provider->getAuthorizationUrl($options);

        // Get the state generated for you and store it to the session.
        $_SESSION['oauth2state'] = $provider->getState();

        // Redirect the user to the authorization URL.
        header('Location: ' . $authorizationUrl);
        exit;
    }

// Check given state against previously stored one to mitigate CSRF attack
    if (empty($_GET['state']) || (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {
        if (isset($_SESSION['oauth2state'])) {
            unset($_SESSION['oauth2state']);
        }

        exit('Invalid state');
    }

    try {
        // Try to get an access token using the authorization code grant.
        $accessToken = $provider->getAccessToken('authorization_code', [
            'code' => $_GET['code']
        ]);
    } catch (Throwable $e) {
        echo "<pre>";
        var_dump($e);
        echo "</pre>";
        die();
    }
    $_SESSION['accessToken'] = $accessToken->jsonSerialize();
}

// We have an access token, which we may use in authenticated
// requests against the service provider's API.
echo 'Access Token: ' . $accessToken->getToken() . "<br>";
echo 'Refresh Token: ' . $accessToken->getRefreshToken() . "<br>";
echo 'Expired in: ' . date('c', $accessToken->getExpires()) . "<br>";

echo '<a href="demo.php">Go to demo.php</a><br/>';
echo '<a href="ltv-demo.php">Go to ltv-demo.php</a><br/>';
echo '<a href="async-demo.php">Go to async-demo.php</a><br/>';
echo '<a href="appearance-demo.php">Go to appearance-demo.php</a><br/>';

