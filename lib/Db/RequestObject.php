<?php

namespace OCA\OIDCLogin\Db;

use JsonSerializable;

use OCP\DB\Types;
use OCP\AppFramework\Db\Entity;

class RequestObject extends Entity implements JsonSerializable
{
    protected $requestUri;
    protected $requestObject;
    protected $creationTimestamp;

    public function __construct()
    {
        $this->addType('id', Types::INTEGER);
        $this->addType('creationTimestamp', Types::INTEGER);
    }

    public function jsonSerialize()
    {
        return [
            'id' => $this->id,
            'request_uri' => $this->requestUri,
            'request_object' => $this->requestObject,
            'creation_timestamp' => $this->creationTimestamp,
        ];
    }
}
