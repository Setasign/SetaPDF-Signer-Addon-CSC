<?php

declare(strict_types=1);

/**
 * @copyright Copyright (c) 2021 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

namespace setasign\SetaPDF\Signer\Module\CSC;

use InvalidArgumentException;
use SetaPDF_Core_Reader_FilePath;
use SetaPDF_Core_Type_Dictionary;
use SetaPDF_Core_Document as Document;
use SetaPDF_Signer_Asn1_Element as Asn1Element;
use SetaPDF_Signer_Digest as Digest;
use SetaPDF_Signer_Asn1_Oid as Asn1Oid;
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
    public static function findHashAndSignAlgorithm(string $signatureAlgorithmOid): array
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
        return ['hashAlgorithm' => $hashAlgorithm, 'signAlgorithm' => $signAlgorithm];
    }

    /**
     * Update CMS SignatureAlgorithmIdentifier according to Probabilistic Signature Scheme (RSASSA-PSS)
     *
     * @param SetaPDF_Signer_Signature_Module_Pades $padesModule
     * @return Asn1Element
     * @throws \SetaPDF_Exception_NotImplemented
     */
    public static function fixPssPadding(
        SetaPDF_Signer_Signature_Module_Pades $padesModule
    ): Asn1Element {
        throw new \SetaPDF_Exception_NotImplemented(
            'Signatures with PSS padding were not tested yet. Please contact support@setasign.com with details of your CSC API.'
        );

//        $padesDigest = $padesModule->getDigest();
//
//        // let's use a salt length of the same size as the hash function output
//        $saltLength = 256 / 8;
//        if ($padesDigest === \SetaPDF_Signer_Digest::SHA_384) {
//            $saltLength = 384 / 8;
//        } elseif ($padesDigest === \SetaPDF_Signer_Digest::SHA_512) {
//            $saltLength = 512 / 8;
//        }
//
//        $cms = $padesModule->getCms();
//
//        $signatureAlgorithmIdentifier = Asn1Element::findByPath('1/0/4/0/4', $cms);
//        $signatureAlgorithmIdentifier->getChild(0)->setValue(
//            Asn1Oid::encode("1.2.840.113549.1.1.10")
//        );
//        $signatureAlgorithmIdentifier->removeChild($signatureAlgorithmIdentifier->getChild(1));
//        $signatureAlgorithmParameters = new Asn1Element(
//            Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
//            '',
//            [
//                new Asn1Element(
//                    Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED,
//                    '',
//                    [
//                        new Asn1Element(
//                            Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
//                            '',
//                            [
//                                new Asn1Element(
//                                    Asn1Element::OBJECT_IDENTIFIER,
//                                    Asn1Oid::encode(Digest::getOid($padesDigest))
//                                ),
//                                new Asn1Element(Asn1Element::NULL)
//                            ]
//                        )
//                    ]
//                ),
//                new Asn1Element(
//                    Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x01",
//                    '',
//                    [
//                        new Asn1Element(
//                            Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
//                            '',
//                            [
//                                new Asn1Element(
//                                    Asn1Element::OBJECT_IDENTIFIER,
//                                    Asn1Oid::encode('1.2.840.113549.1.1.8')
//                                ),
//                                new Asn1Element(
//                                    Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
//                                    '',
//                                    [
//                                        new Asn1Element(
//                                            Asn1Element::OBJECT_IDENTIFIER,
//                                            Asn1Oid::encode(Digest::getOid(
//                                                $padesDigest
//                                            ))
//                                        ),
//                                        new Asn1Element(Asn1Element::NULL)
//                                    ]
//                                )
//                            ]
//                        )
//                    ]
//                ),
//                new Asn1Element(
//                    Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x02", '',
//                    [
//                        new Asn1Element(Asn1Element::INTEGER, \chr($saltLength))
//                    ]
//                )
//            ]
//        );
//        $signatureAlgorithmIdentifier->addChild($signatureAlgorithmParameters);
//
//        return $signatureAlgorithmParameters;
    }

    public static function fixEccSignatures(string $signatureValue): string
    {
        throw new \SetaPDF_Exception_NotImplemented(
            'EC signatures were not tested yet. Please contact support@setasign.com with details of your CSC API.'
        );
        // Let's ensure that the ECDSA-Sig-Value is DER encoded.
        // Some other services (e.g. KMS systems)  return the signature value as raw concatenated "r+s" value.
        // Maybe this also happens by a CSC API? The signature encoding is sadly not defined.
//        try {
//            Asn1Element::parse($signatureValue);
//
//        } catch (\SetaPDF_Signer_Asn1_Exception $e) {
//            /* According to RFC5753 2.1.1:
//             *  - signature MUST contain the DER encoding (as an octet string) of a value of the ASN.1 type
//             *    ECDSA-Sig-Value (see Section 7.2).
//             */
//            $len = strlen($signatureValue);
//
//            $s = \substr($signatureValue, 0, $len / 2);
//            if (\ord($s[0]) & 0x80) { // ensure positive integers
//                $s = "\0" . $s;
//            }
//            $r = \substr($signatureValue, $len / 2);
//            if (\ord($r[0]) & 0x80) { // ensure positive integers
//                $r = "\0" . $r;
//            }
//
//            $signatureValue = new Asn1Element(
//                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
//                '',
//                [
//                    new Asn1Element(Asn1Element::INTEGER, $s),
//                    new Asn1Element(Asn1Element::INTEGER, $r),
//                ]
//            );
//        }
//
//        return $signatureValue;
    }

    /**
     * @var Client
     */
    protected $client;

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
     * @param Client $client
     */
    public function __construct(
        string $accessToken,
        Client $client
    ) {
        $this->accessToken = $accessToken;
        $this->client = $client;
        $this->padesModule = new SetaPDF_Signer_Signature_Module_Pades();
    }

    public function setCredentialId(string $credentialId): void
    {
        $this->credentialId = $credentialId;
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
        ['hashAlgorithm' => $hashAlgorithm, 'signAlgorithm' => $signAlgorithm] = self::findHashAndSignAlgorithm($signatureAlgorithmOid);
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

    public function getPadesDigest(): string
    {
        return $this->padesModule->getDigest();
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

    public function setSignatureValue(string $signatureValue)
    {
        $this->padesModule->setSignatureValue($signatureValue);
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

        // get the hash data from the module
        $padesDigest = $this->padesModule->getDigest();
        $signatureAlgorithmParameters = null;

        if ($this->signAlgorithm === Digest::RSA_PSS_ALGORITHM) {
            $signatureAlgorithmParameters = self::fixPssPadding($this->padesModule);
        }

        $hashData = \base64_encode(hash($padesDigest, $this->padesModule->getDataToSign($tmpPath), true));

        $SAD = $this->client->credentialsAuthorize(
            $this->accessToken,
            $this->credentialId,
            [$hashData],
            $this->pin,
            $this->otp
        )['SAD'];

        $result = $this->client->signaturesSignHash(
            $this->accessToken,
            $this->credentialId,
            $SAD,
            [$hashData],
            $this->signatureAlgorithmOid,
            Digest::$oids[$padesDigest],
            isset($signatureAlgorithmParameters) ? (string)$signatureAlgorithmParameters : null
        );
        $signatureValue = (string) \base64_decode($result['signatures'][0]);

        if ($this->signAlgorithm === Digest::ECDSA_ALGORITHM) {
            $signatureValue = self::fixEccSignatures($signatureValue);
        }

        // pass it to the module
        $this->padesModule->setSignatureValue($signatureValue);

        return (string) $this->padesModule->getCms();
    }
}
