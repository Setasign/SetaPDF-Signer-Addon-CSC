<?php

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\CSC;

use BadMethodCallException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * CSC API Client
 *
 * @see https://cloudsignatureconsortium.org/wp-content/uploads/2020/01/CSC_API_V1_1.0.4.0.pdf
 */
class Client
{
    /**
     * @var ClientInterface PSR-18 HTTP Client implementation.
     */
    protected $httpClient;

    /**
     * @var RequestFactoryInterface PSR-17 HTTP Factory implementation.
     */
    protected $requestFactory;

    /**
     * @var StreamFactoryInterface PSR-17 HTTP Factory implementation.
     */
    protected $streamFactory;

    /**
     * @var string
     */
    protected $apiUri;

    /**
     * @var array|null
     */
    protected $info;

    /**
     * Client constructor.
     *
     * @param string $apiUri
     * @param ClientInterface $httpClient PSR-18 HTTP Client implementation.
     * @param RequestFactoryInterface $requestFactory PSR-17 HTTP Factory implementation.
     * @param StreamFactoryInterface $streamFactory PSR-17 HTTP Factory implementation.
     */
    public function __construct(
        string $apiUri,
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory
    ) {
        $this->apiUri = $apiUri;
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;
    }

    /**
     * Helper method to fetch the oauth2 url endpoints.
     *
     * @return array
     * @throws ClientExceptionInterface
     */
    public function getOauth2Info(): array
    {
        $info = $this->info();
        if (!\array_key_exists('oauth2', $info) || $info['oauth2'] === '') {
            throw new BadMethodCallException('OAuth2 isn\'t supported by your CSC API.');
        }

        // this should contain the base URI of the OAuth 2.0 authorization server endpoint
        $baseUrl = $info['oauth2'];
        // some endpoints seem to ignore the official documentation for oauth2 value, so we try to fix this here
        if (strpos($baseUrl, '/oauth2/authorize') !== false) {
            $baseUrl = substr($info['oauth2'], 0, -strlen('/oauth2/authorize'));
        }

        return [
            'urlAuthorize' => $baseUrl . '/oauth2/authorize',
            'urlAccessToken' => $baseUrl . '/oauth2/token',
            'urlResourceOwnerDetails' => $baseUrl . '/oauth2/resource'
        ];
    }

    /**
     * Helper method to handle errors in json_decode
     *
     * @param string $json
     * @param bool $assoc
     * @param int $depth
     * @param int $options
     * @return mixed
     * @throws ClientException
     */
    protected function json_decode(string $json, bool $assoc = true, int $depth = 512, int $options = 0)
    {
        // Clear json_last_error()
        \json_encode(null);

        $data = @\json_decode($json, $assoc, $depth, $options);

        if (\json_last_error() !== JSON_ERROR_NONE) {
            throw new \InvalidArgumentException(\sprintf(
                'Unable to decode JSON: %s',
                \json_last_error_msg()
            ));
        }

        return $data;
    }

    /**
     * @param string $path
     * @param string|null $accessToken
     * @param array $inputData
     * @return array
     * @throws ClientExceptionInterface
     * @throws ClientException
     */
    public function call(string $path, ?string $accessToken = null, array $inputData = []): array
    {
        if (count($inputData) === 0) {
            $inputData = '{}';
        } else {
            $inputData = \json_encode($inputData);
        }

        $request = (
            $this->requestFactory->createRequest('POST', $this->apiUri . $path)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streamFactory->createStream($inputData))
        );
        if ($accessToken !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $accessToken);
        }

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            // $body in the message is kept for BC, don't rely on it but use $e->getData() instead!
            throw new ClientException('Error on ' . $path . ': ' . $response->getBody(), $response);
        }

        return $this->json_decode((string) $response->getBody());
    }

    /**
     * Returns information about the remote service and the list of the API methods it supports.
     * This method SHALL be implemented by any remote service conforming to this specification.
     *
     * Note: the result of this method is memoized.
     *
     * @param string|null $lang
     * @return array
     * @throws ClientExceptionInterface
     * @see CSC API 11.1 /info
     */
    public function info(?string $lang = null): array
    {
        if ($this->info === null || !\array_key_exists($lang, $this->info)) {
            $inputData = [];
            if ($lang !== null) {
                $inputData['lang'] = $lang;
            }
            $this->info[$lang ?? 'none'] = $this->call('/info', null, $inputData);
        }
        return $this->info[$lang ?? 'none'];
    }

    /**
     * Returns the list of credentials associated with a user identifier. A user MAY have one or multiple credentials
     * hosted by a single remote signing service provider.
     *
     * @param string $accessToken
     * @param string|null $userID
     * @param int|null $maxResults
     * @param string|null $pageToken
     * @param string|null $clientData
     * @return array
     * @throws ClientExceptionInterface|ClientException
     * @see CSC API 11.4 /credentials/list
     */
    public function credentialsList(
        string $accessToken,
        ?string $userID = null,
        ?int $maxResults = null,
        ?string $pageToken = null,
        ?string $clientData = null
    ): array {
        $inputData = [];
        if ($userID !== null) {
            $inputData['userID'] = $userID;
        }
        if ($maxResults !== null) {
            $inputData['maxResults'] = $maxResults;
        }
        if ($pageToken !== null) {
            $inputData['pageToken'] = $pageToken;
        }
        if ($clientData !== null) {
            $inputData['clientData'] = $clientData;
        }

        return $this->call('/credentials/list', $accessToken, $inputData);
    }

    /**
     * Retrieve the credential and return the main identity information and the public key certificate or the
     * certificate chain associated to it.
     *
     * @param string $accessToken
     * @param string|null $credentialID
     * @param string|null $certificates
     * @param bool|null $certInfo
     * @param bool|null $authInfo
     * @param string|null $lang
     * @param string|null $clientData
     * @return array
     * @throws ClientExceptionInterface|ClientException
     * @see CSC API 11.5 /credentials/info
     */
    public function credentialsInfo(
        string $accessToken,
        string $credentialID = null,
        ?string $certificates = null,
        ?bool $certInfo = null,
        ?bool $authInfo = null,
        ?string $lang = null,
        ?string $clientData = null
    ): array {
        $inputData = [
            'credentialID' => $credentialID
        ];
        if ($certificates !== null) {
            $inputData['certificates'] = $certificates;
        }
        if ($certInfo !== null) {
            $inputData['certInfo'] = $certInfo;
        }
        if ($authInfo !== null) {
            $inputData['authInfo'] = $authInfo;
        }
        if ($lang !== null) {
            $inputData['lang'] = $lang;
        }
        if ($clientData !== null) {
            $inputData['clientData'] = $clientData;
        }

        return $this->call('/credentials/info', $accessToken, $inputData);
    }

    /**
     * Start an online One-Time Password (OTP) generation mechanism associated with a credential and managed by the
     * remote service. This will generate a dynamic one-time password that will be delivered to the user who owns the
     * credential through an agreed communication channel managed by the remote service (e.g. SMS, email, app, etc.).
     *
     * This method SHOULD only be used with “online” OTP generators. In case of “offline” OTP, the signature
     * application SHOULD NOT invoke this method because the OTP can be generated autonomously by the user.
     *
     * @param string $accessToken
     * @param string $credentialID
     * @param string|null $clientData
     * @return array
     * @throws ClientExceptionInterface|ClientException
     * @see CSC API 11.8 /credentials/sendOTP
     */
    public function credentialsSendOTP(string $accessToken, string $credentialID, ?string $clientData = null): array
    {
        $inputData = [
            'credentialID' => $credentialID,
        ];

        if ($clientData !== null) {
            $inputData['clientData'] = $clientData;
        }

        return $this->call('/credentials/sendOTP', $accessToken, $inputData);
    }

    /**
     * Authorize the access to the credential for remote signing, according to the authorization mechanisms associated
     * to it. This method returns the Signature Activation Data (SAD) required to authorize the signatures/signHash
     * method, as defined in section 11.9.
     *
     * @param string $accessToken
     * @param string $credentialID
     * @param string[] $hash
     * @param string|null $PIN
     * @param string|null $OTP
     * @param string|null $description
     * @param string|null $clientData
     * @return array
     * @throws ClientExceptionInterface|ClientException
     * @see CSC API 11.6 /credentials/authorize
     */
    public function credentialsAuthorize(
        string $accessToken,
        string $credentialID,
        array $hash,
        ?string $PIN = null,
        ?string $OTP = null,
        ?string $description = null,
        ?string $clientData = null
    ): array {
        $inputData = [
            'credentialID' => $credentialID,
            'numSignatures' => count($hash),
            'hash' => $hash,
        ];
        if ($PIN !== null) {
            $inputData['PIN'] = $PIN;
        }
        if ($OTP !== null) {
            $inputData['OTP'] = $OTP;
        }
        if ($description !== null) {
            $inputData['description'] = $description;
        }
        if ($clientData !== null) {
            $inputData['clientData'] = $clientData;
        }

        return $this->call('/credentials/authorize', $accessToken, $inputData);
    }

    /**
     * Calculate the remote digital signature of one or multiple hash values provided in input. This method requires
     * credential authorization in the form of Signature Activation Data (SAD).
     *
     * @param string $accessToken
     * @param string $credentialID
     * @param string $SAD
     * @param string[] $hash
     * @param string $signAlgo
     * @param string|null $hashAlgo
     * @param string|null $signAlgoParams
     * @param string|null $clientData
     * @return array
     * @throws ClientExceptionInterface|ClientException
     * @see CSC API 11.9 /signatures/signHash
     */
    public function signaturesSignHash(
        string $accessToken,
        string $credentialID,
        string $SAD,
        array $hash,
        string $signAlgo,
        ?string $hashAlgo = null,
        ?string $signAlgoParams = null,
        ?string $clientData = null
    ): array {
        $inputData = [
            'credentialID' => $credentialID,
            'SAD' => $SAD,
            'hash' => $hash,
        ];
        if ($hashAlgo !== null) {
            $inputData['hashAlgo'] = $hashAlgo;
        }
        if ($signAlgo !== null) {
            $inputData['signAlgo'] = $signAlgo;
        }
        if ($signAlgoParams !== null) {
            $inputData['signAlgoParams'] = $signAlgoParams;
        }
        if ($clientData !== null) {
            $inputData['clientData'] = $clientData;
        }

        return $this->call('/signatures/signHash', $accessToken, $inputData);
    }
}
