<?php

/**
 * @copyright Copyright (c) 2026 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\CSC;

use Psr\Http\Message\ResponseInterface;
use setasign\SetaPDF2\Signer\Exception;

class ClientException extends Exception
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
