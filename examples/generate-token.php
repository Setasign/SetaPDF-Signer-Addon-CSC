<?php

use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;

require_once(__DIR__ . '/../vendor/autoload.php');

/**
 * This file uses league/oauth2-client (https://github.com/thephpleague/oauth2-client) as oauth implementation.
 */

$settings = require __DIR__ . '/settings.php';

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();

$provider = new GenericProvider([
    'clientId' => $settings['clientId'],
    'clientSecret' => $settings['clientSecret'],
    'redirectUri' => $settings['oauth2redirectUrl'],
    'urlAuthorize' => $settings['oauth2urlAuthorize'],
    'urlAccessToken' => $settings['oauth2urlAccessToken'],
    'urlResourceOwnerDetails' => $settings['oauth2urlResourceOwnerDetails'],
]);

if (isset($_GET['reset'])) {
    $_SESSION = [];
}

if (isset($_SESSION['accessToken'])) {
    $accessToken = new AccessToken($_SESSION['accessToken']);
    if ($accessToken->hasExpired()) {
        $accessToken = $provider->getAccessToken('refresh_token', [
            'refresh_token' => $accessToken->getRefreshToken()
        ]);

        $_SESSION['accessToken'] = $accessToken->jsonSerialize();
    }
} else {
// If we don't have an authorization code then get one
    if (!isset($_GET['code'])) {
        // Fetch the authorization URL from the provider; this returns the
        // urlAuthorize option and generates and applies any necessary parameters
        // (e.g. state).
        $authorizationUrl = $provider->getAuthorizationUrl([
            'scope' => $settings['oauth2scope']
        ]);

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
        var_dump($e);
        die();
    }
    $_SESSION['accessToken'] = $accessToken->jsonSerialize();
}

// We have an access token, which we may use in authenticated
// requests against the service provider's API.
echo 'Access Token: ' . $accessToken->getToken() . "<br>";
echo 'Refresh Token: ' . $accessToken->getRefreshToken() . "<br>";
echo 'Expired in: ' . date('c', $accessToken->getExpires()) . "<br>";
echo 'Already expired? ' . ($accessToken->hasExpired() ? 'expired' : 'not expired') . "<br>";

