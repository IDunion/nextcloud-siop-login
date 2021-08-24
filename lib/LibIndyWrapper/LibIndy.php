<?php

class LibIndy {
    private $ffi;

    function __construct() {
        $this->ffi = $this->getFFI();
    }

    private function getFFI() {
        return FFI::load(__DIR__ . "/indy.h");
    }

    private function schemaCb(int $command_handle, int $err, string $id, string $schema_json) {
        $schema = new SchemaResult($id, $schema_json, $err);
        $queue = msg_get_queue($command_handle);
        msg_send($queue, 1, $schema);
    }

    public function createSchema(string $did, string $name, string $version, string $attr) {       
        $future = new Future(1);
        $result = $this->ffi->indy_issuer_create_schema($future->getQueueKey(), $did, $name, $version, $attr, [__CLASS__, "schemaCb"]);

        if ($result != 0) {
            $future->msg = $result;
        }

        return $future;
    }

    private function verifyProofCb(int $command_handle, int $error, bool $valid) {
        $queue = msg_get_queue($command_handle);
        msg_send($queue, 1, $valid);
    }

    public function verifierVerifyProof($proofRequestJson, $proofJson, $schemasJson, $credentialDefsJsons, $revRegDefsJson, $revRegsJson) {
        $future = new Future(2);
        $result = $this->ffi->indy_verifier_verify_proof($future->getQueueKey(), $proofRequestJson, $proofJson, $schemasJson, $credentialDefsJsons, $revRegDefsJson, $revRegsJson,  [__CLASS__, "verifyProofCb"]);
    
        if ($result != 0) {
            $future->msg = $result;
        }

        return $future;
    }
}

class SchemaResult {
    private $id;
    private $schemaJson;
    private $error;

    function __construct(string $id, string $schemaJson, int $error) {
        $this->id = $id;
        $this->schemaJson = $schemaJson;
        $this->error = $error;
    }

    function getId() {
        return $this->id;
    }

    function getSchemaJson() {
        return $this->schemaJson;
    }

    function getError() {
        return $this->error;
    }
}

class Future {
    private $queue;
    private $q_key;
    private $msg_type;
    public $msg = NULL;

    function __construct(int $msg_type) {
        $this->msg_type = $msg_type;
        $this->q_key = random_int(0,10000);
        $this->queue = msg_get_queue($this->q_key);
    }

    function get() {
        if ($this->msg == NULL) {
            msg_receive($this->queue, 1, $this->msg_type, 65536, $this->msg);
        }
        return $this->msg;
    }

    function getQueueKey(): int {
        return $this->q_key;
    }
}