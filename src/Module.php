<?php

/**
 * @copyright Copyright (c) 2021 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

namespace setasign\SetaPDF\Signer\Module\CSC;

use Exception;
use InvalidArgumentException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use SetaPDF_Core_Reader_FilePath;
use SetaPDF_Core_Type_Dictionary;
use SetaPDF_Core_Document as Document;
use SetaPDF_Signer_Asn1_Element as Asn1Element;
use SetaPDF_Signer_Asn1_Oid as Asn1Oid;
use SetaPDF_Signer_Digest as Digest;
use SetaPDF_Signer_Exception;
use SetaPDF_Signer_Signature_DictionaryInterface;
use SetaPDF_Signer_Signature_DocumentInterface;
use SetaPDF_Signer_Signature_Module_ModuleInterface;
use SetaPDF_Signer_Signature_Module_Pades;

/**
 * Class Module
 *
 * @see https://cloudsignatureconsortium.org/wp-content/uploads/2020/01/CSC_API_V1_1.0.4.0.pdf
 */
class Module implements
    SetaPDF_Signer_Signature_Module_ModuleInterface,
    SetaPDF_Signer_Signature_DictionaryInterface,
    SetaPDF_Signer_Signature_DocumentInterface
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
     * @var string|null
     */
    protected $accessToken;

    /**
     * @var string|null
     */
    protected $credentialId;

    /**
     * @var string
     */
    protected $apiUri;

    /**
     * @var string|null
     */
    protected $signatureAlgorithmOid;

    /**
     * @var string
     */
    protected $signAlgorithm;

    /**
     * @var null|string
     */
    protected $pin;

    /**
     * @var null|string
     */
    protected $otp;

    /**
     * Module constructor.
     *
     * @param string $accessToken
     * @param string $apiUri
     * @param ClientInterface $httpClient PSR-18 HTTP Client implementation.
     * @param RequestFactoryInterface $requestFactory PSR-17 HTTP Factory implementation.
     * @param StreamFactoryInterface $streamFactory PSR-17 HTTP Factory implementation.
     */
    public function __construct(
        string $accessToken,
        string $apiUri,
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory
    ) {
        $this->accessToken = $accessToken;
        $this->apiUri = $apiUri;
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;
        $this->padesModule = new SetaPDF_Signer_Signature_Module_Pades();
    }

    /**
     * Returns the list of credentials associated with a user identifier. A user MAY have one or multiple credentials
     * hosted by a single remote signing service provider.
     *
     * @see CSC API /credentials/list
     * @return array
     * @throws Exception
     * @throws ClientExceptionInterface
     */
    public function fetchCredentialsList(): array
    {
        $request = (
            $this->requestFactory->createRequest('POST', $this->apiUri . '/credentials/list')
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Authorization', 'Bearer ' . $this->accessToken)
            ->withBody($this->streamFactory->createStream('{}'))
        );
        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on fetching the credentials: ' . $response->getBody());
        }

        $responseBody = $this->json_decode($response->getBody());
        return $responseBody['credentialIDs'];
    }

    public function setCredentialId(string $credentialId): void
    {
        $this->credentialId = $credentialId;
    }

    /**
     * Retrieve the credential and return the main identity information and the public key certificate or the
     * certificate chain associated to it.
     *
     * @see CSC API /credentials/info
     * @return array
     * @throws ClientExceptionInterface
     * @throws Exception
     */
    public function fetchCredentialsInfo(): array
    {
        $request = (
            $this->requestFactory->createRequest('POST', $this->apiUri . '/credentials/info')
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Authorization', 'Bearer ' . $this->accessToken)
            ->withBody($this->streamFactory->createStream(\json_encode([
                'credentialID' => $this->credentialId,
                'certificates' => 'chain',
                'authInfo' => true,
                'certInfo' => true
            ])))
        );
        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on fetching the credentials: ' . $response->getBody());
        }

        return $this->json_decode($response->getBody());
    }

    public function setOtp(string $otp): void
    {
        $this->otp = $otp;
    }

    public function setPin(string $pin): void
    {
        $this->pin = $pin;
    }

    /**
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
     * @param $certificate
     * @throws \SetaPDF_Signer_Asn1_Exception
     */
    public function setCertificate($certificate)
    {
        $this->padesModule->setCertificate($certificate);
    }

    /**
     * @param string $signatureAlgorithmOid
     */
    public function setSignatureAlgorithmOid(string $signatureAlgorithmOid)
    {
        $found = false;
        $hashAlgorithm = $signAlgorithm = null;
        foreach (Digest::$encryptionOids as $signAlgorithm => $hashAlgorithms) {
            $hashAlgorithm = \array_search($signatureAlgorithmOid, $hashAlgorithms, true);
            if ($hashAlgorithm === false) {
                continue;
            }
            $found = true;
            break;
        }

        if (!$found) {
            throw new InvalidArgumentException(\sprintf('Unknown signature algorithm OID "%s"', $signatureAlgorithmOid));
        }

        $this->padesModule->setDigest($hashAlgorithm);
        $this->signAlgorithm = $signAlgorithm;
        $this->signatureAlgorithmOid = $signatureAlgorithmOid;
    }

    /**
     * @return string|null
     */
    public function getSignatureAlgorithmOid(): ?string
    {
        return $this->signatureAlgorithmOid;
    }

    /**
     * Add additional certificates which are placed into the CMS structure.
     *
     * @param array|\SetaPDF_Signer_X509_Collection $extraCertificates PEM encoded certificates or pathes to PEM encoded
     *                                                                 certificates.
     * @throws \SetaPDF_Signer_Asn1_Exception
     */
    public function setExtraCertificates($extraCertificates)
    {
        $this->padesModule->setExtraCertificates($extraCertificates);
    }

    /**
     * Adds an OCSP response which will be embedded in the CMS structure.
     *
     * @param string|\SetaPDF_Signer_Ocsp_Response $ocspResponse DER encoded OCSP response or OCSP response instance.
     * @throws SetaPDF_Signer_Exception
     */
    public function addOcspResponse($ocspResponse)
    {
        $this->padesModule->addOcspResponse($ocspResponse);
    }

    /**
     * Adds an CRL which will be embedded in the CMS structure.
     *
     * @param string|\SetaPDF_Signer_X509_Crl $crl
     */
    public function addCrl($crl)
    {
        $this->padesModule->addCrl($crl);
    }

    /**
     * @inheritDoc
     */
    public function updateSignatureDictionary(SetaPDF_Core_Type_Dictionary $dictionary)
    {
        $this->padesModule->updateSignatureDictionary($dictionary);
    }

    /**
     * @inheritDoc
     */
    public function updateDocument(Document $document)
    {
        $this->padesModule->updateDocument($document);
    }

    /**
     * Get the complete Cryptographic Message Syntax structure.
     *
     * @return Asn1Element
     * @throws SetaPDF_Signer_Exception
     */
    public function getCms()
    {
        return $this->padesModule->getCms();
    }

    /**
     * @inheritDoc
     */
    public function createSignature(SetaPDF_Core_Reader_FilePath $tmpPath)
    {
        // ensure certificate
        $certificate = $this->padesModule->getCertificate();
        if ($certificate === null) {
            throw new \BadMethodCallException('Missing certificate!');
        }

        if ($this->signatureAlgorithmOid === null) {
            throw new \BadMethodCallException('Missing signature algorithm!');
        }

        // todo
//         // update CMS SignatureAlgorithmIdentifier according to Probabilistic Signature Scheme (RSASSA-PSS)
//        if ($this->signAlgorithm === Digest::RSA_PSS_ALGORITHM) {
//            // Here https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign#jsonwebkeysignaturealgorithm
//            // the algorihms are linked to https://tools.ietf.org/html/rfc7518#section-3.5 which says:
//            // "The size of the salt value is the same size as the hash function output."
//            $saltLength = 256 / 8;
//            if ($signatureAlgorithm === 'PS384') {
//                $saltLength = 384 / 8;
//            } elseif ($signatureAlgorithm === 'PS512') {
//                $saltLength = 512 / 8;
//            }
//
//            $cms = $this->padesModule->getCms();
//
//            $signatureAlgorithmIdentifier = Asn1Element::findByPath('1/0/4/0/4', $cms);
//            $signatureAlgorithmIdentifier->getChild(0)->setValue(
//                Asn1Oid::encode("1.2.840.113549.1.1.10")
//            );
//            $signatureAlgorithmIdentifier->removeChild($signatureAlgorithmIdentifier->getChild(1));
//            $signatureAlgorithmIdentifier->addChild(new Asn1Element(
//                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
//                '',
//                [
//                    new Asn1Element(
//                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED,
//                        '',
//                        [
//                            new Asn1Element(
//                                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
//                                '',
//                                [
//                                    new Asn1Element(
//                                        Asn1Element::OBJECT_IDENTIFIER,
//                                        Asn1Oid::encode(Digest::getOid($this->padesModule->getDigest()))
//                                    ),
//                                    new Asn1Element(Asn1Element::NULL)
//                                ]
//                            )
//                        ]
//                    ),
//                    new Asn1Element(
//                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x01",
//                        '',
//                        [
//                            new Asn1Element(
//                                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
//                                '',
//                                [
//                                    new Asn1Element(
//                                        Asn1Element::OBJECT_IDENTIFIER,
//                                        Asn1Oid::encode('1.2.840.113549.1.1.8')
//                                    ),
//                                    new Asn1Element(
//                                        Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
//                                        '',
//                                        [
//                                            new Asn1Element(
//                                                Asn1Element::OBJECT_IDENTIFIER,
//                                                Asn1Oid::encode(Digest::getOid(
//                                                    $this->padesModule->getDigest()
//                                                ))
//                                            ),
//                                            new Asn1Element(Asn1Element::NULL)
//                                        ]
//                                    )
//                                ]
//                            )
//                        ]
//                    ),
//                    new Asn1Element(
//                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x02", '',
//                        [
//                            new Asn1Element(Asn1Element::INTEGER, \chr($saltLength))
//                        ]
//                    )
//                ]
//            ));
//        }

        // get the hash data from the module
        $padesDigest = $this->padesModule->getDigest();
        $hashData = \base64_encode(hash($padesDigest, $this->padesModule->getDataToSign($tmpPath), true));
        $authorizeData = [
            'credentialID' => $this->credentialId,
            'numSignatures' => 1,
            'hash' => [
                $hashData
            ],
        ];
        if ($this->pin !== null) {
            $authorizeData['PIN'] = $this->pin;
        }

        if ($this->otp !== null) {
            $authorizeData['OTP'] = $this->otp;
        }

        $request = (
            $this->requestFactory->createRequest('POST', $this->apiUri . '/credentials/authorize')
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Authorization', 'Bearer ' . $this->accessToken)
            ->withBody($this->streamFactory->createStream(\json_encode($authorizeData)))
        );
        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on authorize the credentials: ' . $response->getBody());
        }
        $sad = $this->json_decode($response->getBody())['SAD'];

        $request = (
            $this->requestFactory->createRequest('POST', $this->apiUri . '/signatures/signHash')
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Authorization', 'Bearer ' . $this->accessToken)
            ->withBody($this->streamFactory->createStream(\json_encode([
                'credentialID' => $this->credentialId,
                'SAD' => $sad,
                'hash' => [
                    $hashData
                ],
                'signAlgo' => $this->signatureAlgorithmOid,
//            'hashAlgo' => Digest::$oids[$padesDigest]
            ])))
        );
        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new Exception('Error on signing the hash: ' . $response->getBody());
        }
        $signatureValue = \base64_decode($this->json_decode($response->getBody())['signatures'][0]);

        // TODO double check this
        if ($this->signAlgorithm === Digest::ECDSA_ALGORITHM) {
            // THIS NEEDS TO BE USED TO FIX EC SIGNATURES
            $len = strlen($signatureValue);

            $s = substr($signatureValue, 0, $len / 2);
            if (ord($s[0]) & 0x80) { // ensure positive integers
                $s = "\0" . $s;
            }
            $r = substr($signatureValue, $len / 2);
            if (ord($r[0]) & 0x80) { // ensure positive integers
                $r = "\0" . $r;
            }

            $signatureValue = new Asn1Element(
                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                '',
                [
                    new Asn1Element(Asn1Element::INTEGER, $s),
                    new Asn1Element(Asn1Element::INTEGER, $r),
                ]
            );
        }

        // pass it to the module
        $this->padesModule->setSignatureValue((string) $signatureValue);

        return (string) $this->padesModule->getCms();
    }
}
