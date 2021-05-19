<?php

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\CSC;

use Exception;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use SetaPDF_Signer_Signature_Module_Pades;

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
     * @var SetaPDF_Signer_Signature_Module_Pades Internal pades module.
     */
    protected $padesModule;

    /**
     * @var string
     */
    protected $apiUri;

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
     * Helper method to handle errors in json_decode
     *
     * @param string $json
     * @param bool $assoc
     * @param int $depth
     * @param int $options
     * @return mixed
     * @throws Exception
     */
    protected function json_decode(string $json, bool $assoc = true, int $depth = 512, int $options = 0)
    {
        // Clear json_last_error()
        \json_encode(null);

        $data = @\json_decode($json, $assoc, $depth, $options);

        if (\json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception(\sprintf(
                'Unable to decode JSON: %s',
                \json_last_error_msg()
            ));
        }

        return $data;
    }

    /**
     * Returns information about the remote service and the list of the API methods it supports.
     * This method SHALL be implemented by any remote service conforming to this specification.
     *
     * @param array $inputData
     * @return array
     * @throws ClientExceptionInterface
     * @throws Exception
     * @see CSC API 11.1 /info
     */
    public function info(array $inputData = []): array
    {
        $request = (
            $this->requestFactory->createRequest('POST', $this->apiUri . '/info')
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streamFactory->createStream(\json_encode($inputData, JSON_FORCE_OBJECT)))
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on /info: ' . $response->getBody());
        }

        return $this->json_decode((string) $response->getBody());
    }

    /**
     * Returns the list of credentials associated with a user identifier. A user MAY have one or multiple credentials
     * hosted by a single remote signing service provider.
     *
     * @param string $accessToken
     * @param array $inputData
     * @return array
     * @throws ClientExceptionInterface
     * @throws Exception
     * @see CSC API 11.4 /credentials/list
     */
    public function credentialsList(string $accessToken, array $inputData = []): array
    {
        $request = (
            $this->requestFactory->createRequest('POST', $this->apiUri . '/credentials/list')
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Authorization', 'Bearer ' . $accessToken)
            ->withBody($this->streamFactory->createStream(\json_encode($inputData, JSON_FORCE_OBJECT)))
        );
        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on /credentials/list: ' . $response->getBody());
        }

        return $this->json_decode((string) $response->getBody());
    }

    /**
     * Retrieve the credential and return the main identity information and the public key certificate or the
     * certificate chain associated to it.
     *
     * @param string $accessToken
     * @param array $inputData
     * @return array
     * @throws ClientExceptionInterface
     * @throws Exception
     * @see CSC API 11.5 /credentials/info
     */
    public function credentialsInfo(string $accessToken, array $inputData = []): array
    {
        $request = (
            $this->requestFactory->createRequest('POST', $this->apiUri . '/credentials/info')
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Authorization', 'Bearer ' . $accessToken)
            ->withBody($this->streamFactory->createStream(\json_encode($inputData, JSON_FORCE_OBJECT)))
        );
        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on /credentials/info: ' . $response->getBody());
        }

        return $this->json_decode((string) $response->getBody());
    }

    /**
     * @param string $accessToken
     * @param array $inputData
     * @return array
     * @throws ClientExceptionInterface
     * @throws Exception
     * @see CSC API 11.6 /credentials/authorize
     */
    public function credentialsAuthorize(string $accessToken, array $inputData): array
    {
        $request = (
            $this->requestFactory->createRequest('POST', $this->apiUri . '/credentials/authorize')
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Authorization', 'Bearer ' . $accessToken)
            ->withBody($this->streamFactory->createStream(\json_encode($inputData)))
        );
        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on /credentials/authorize: ' . $response->getBody());
        }
        return $this->json_decode((string) $response->getBody());
    }

    /**
     * @param string $accessToken
     * @param array $inputData
     * @return array
     * @throws ClientExceptionInterface
     * @throws Exception
     * @see CSC API 11.9 /signatures/signHash
     */
    public function signaturesSignHash(string $accessToken, array $inputData): array
    {
        $request = (
            $this->requestFactory->createRequest('POST', $this->apiUri . '/signatures/signHash')
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Authorization', 'Bearer ' . $accessToken)
            ->withBody($this->streamFactory->createStream(\json_encode($inputData)))
        );
        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on /signatures/signHash: ' . $response->getBody());
        }
        return $this->json_decode((string) $response->getBody());
    }
}
