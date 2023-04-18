<?php

/**
 * @copyright Copyright (c) 2021 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

namespace setasign\SetaPDF\Signer\Module\CSC;

use Psr\Http\Message\ResponseInterface;
use SetaPDF_Signer_Exception;

class ClientException extends SetaPDF_Signer_Exception
{
    /**
     * @var ResponseInterface
     */
    protected $response;

    public function __construct($message, ResponseInterface $response)
    {
        parent::__construct($message);
        $this->response = $response;
    }

    public function getResponse()
    {
        return $this->response;
    }
}
