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
        $schema = new SchemaResult($err, $id, $schema_json);
        $queue = \msg_get_queue($command_handle);
        \msg_send($queue, 1, $schema);
    }

    public function createSchema(string $did, string $name, string $version, string $attr) {       
        $future = new Future(1);
        $result = $this->ffi->indy_issuer_create_schema($future->getQueueKey(), $did, $name, $version, $attr, [__CLASS__, "schemaCb"]);

        if ($result != 0) {
            throw new LibIndyException(NULL, $result);
        }

        return $future;
    }

    private function voidCb(int $command_handle, int $err) {
        $queue = \msg_get_queue($command_handle);
        \msg_send($queue, 3, new BaseResult($err));
    }

    /**
     * @param string $configName : arbitrary string
     * @param string $config : JSON of the format {"genesis_txn": "--PATH TO GENESIS FILE--"}
     */
    public function createPoolLedgerConfig(string $configName, ?string $config) {
        $future = new Future(3);
        $result = $this->ffi->indy_create_pool_ledger_config($future->getQueueKey(), $configName, $config,  [__CLASS__, "voidCb"]);
    
        if ($result != 0) {
            throw new LibIndyException(NULL, $result);
        }

        return $future;
    }

    public function deletePoolLedgerConfig(string $configName) {
        $future = new Future(3);
        $result = $this->ffi->indy_delete_pool_ledger_config($future->getQueueKey(), $configName, [__CLASS__, "voidCb"]);
    
        if ($result != 0) {
            throw new LibIndyException(NULL, $result);
        }

        return $future;
    }

    private function verifyProofCb(int $command_handle, int $error, bool $valid) {
        $queue = \msg_get_queue($command_handle);
        \msg_send($queue, 2, $valid);
    }

    public function verifierVerifyProof($proofRequestJson, $proofJson, $schemasJson, $credentialDefsJsons, $revRegDefsJson, $revRegsJson) {
        $future = new Future(2);
        $result = $this->ffi->indy_verifier_verify_proof($future->getQueueKey(), $proofRequestJson, $proofJson, $schemasJson, $credentialDefsJsons, $revRegDefsJson, $revRegsJson,  [__CLASS__, "verifyProofCb"]);
    
        if ($result != 0) {
            throw new LibIndyException(NULL, $result);
        }

        return $future;
    }

    /**
     * @param string $pattern : e.g. "trace" to see all logs
     */
    public function setDefaultLogger(string $pattern) {
        $result = $this->ffi->indy_set_default_logger($pattern);
    
        if ($result != 0) {
            throw new LibIndyException(NULL, $result);
        }
    }
}

class BaseResult {
    private $error;

    function __construct(int $error) {
        $this->error = $error;
    }

    function getError() {
        return $this->error;
    }

    function success() {
        return $this->error == 0;
    }
}

class SchemaResult extends BaseResult {
    private $id;
    private $schemaJson;

    function __construct(int $error, string $id, string $schemaJson) {
        parent::__construct($error);
        $this->id = $id;
        $this->schemaJson = $schemaJson;
    }

    function getId() {
        return $this->id;
    }

    function getSchemaJson() {
        return $this->schemaJson;
    }
}

class Future {
    private $queue;
    private $q_key;
    private $msg_type;
    public ?BaseResult $msg;

    function __construct(int $msg_type) {
        $this->msg_type = $msg_type;
        $this->q_key = \random_int(0,10000);
        $this->queue = \msg_get_queue($this->q_key);
    }

    /**
     * Returns the result of the library call and waits
     * if necessary for the result.
     */
    function get() {
        \msg_receive($this->queue, $this->msg_type, $received_msg_type, 65536, $this->msg);
        \msg_remove_queue($this->queue);
        if (!$this->msg->success()) {
            throw new LibIndyException(NULL, $this->msg->getError());
        }
        return $this->msg;
    }

    function getQueueKey(): int {
        return $this->q_key;
    }
}

class LibIndyException extends Exception {
    public function __toString() {
        return "LibIndyException code: " . $this->code . " message: " . $this->message;
    }
 }