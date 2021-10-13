<?php

namespace OCA\OIDCLogin\Db;

use JsonSerializable;

use OCP\DB\Types;
use OCP\AppFramework\Db\Entity;

class Token extends Entity implements JsonSerializable {
    protected $nonce;
    protected $idToken;
    protected $vpToken;
    protected $used;
    protected $creationTimestamp;

    public function __construct() {
        $this->addType('id', Types::INTEGER);
        $this->addType('used', Types::BOOLEAN);
        $this->addType('creationTimestamp', Types::INTEGER);
    }

    public function jsonSerialize() {
        return [
            'id' => $this->id,
            'nonce' => $this->nonce,
            'id_token' => $this->idToken,
            'vp_token' => $this->vpToken,
            'used' => $this->used,
            'creation_timestamp' => $this->creationTimestamp,
        ];
    }
}

?>