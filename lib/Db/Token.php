<?php

namespace OCA\OIDCLogin\Db;

use JsonSerializable;

use OCP\DB\Types;
use OCP\AppFramework\Db\Entity;

class Token extends Entity implements JsonSerializable
{
    protected $presentationId;
    protected $presentationSubmission;
    protected $vpToken;
    protected $used;
    protected $creationTimestamp;

    public function __construct()
    {
        $this->addType('id', Types::INTEGER);
        $this->addType('used', Types::BOOLEAN);
        $this->addType('creationTimestamp', Types::INTEGER);
    }

    public function jsonSerialize()
    {
        return [
            'id' => $this->id,
            'presentation_id' => $this->presentationId,
            'presentation_submission' => $this->presentationSubmission,
            'vp_token' => $this->vpToken,
            'used' => $this->used,
            'creation_timestamp' => $this->creationTimestamp,
        ];
    }
}
