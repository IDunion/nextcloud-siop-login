<?php

namespace OCA\OIDCLogin\LibIndyWrapper;

class LibIndy {
    private $ffi;

    function __construct() {
        $this->ffi = $this->getFFI();
    }

    private function getFFI() {
        return \FFI::load(__DIR__ . "/indy.h");
    }

    private function parseResponseCb(int $command_handle, int $err, string $id, string $schema_json) {       
        $schema = new ParseResponseResult($err, $id, $schema_json);
        $queue = \msg_get_queue($command_handle);
        \msg_send($queue, 1, $schema);
    }

    public function createSchema(string $did, string $name, string $version, string $attr) {       
        $future = new Future(1);
        $result = $this->ffi->indy_issuer_create_schema($future->getQueueKey(), $did, $name, $version, $attr, [__CLASS__, "parseResponseCb"]);

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

    private function openPoolCb(int $command_handle, int $err, int $pool_handle) {
        $queue = \msg_get_queue($command_handle);
        \msg_send($queue, 4, new PoolOpenResult($err, $pool_handle));
    }

    public function openPoolLedger(string $configName, string $config = NULL) {
        $future = new Future(4);
        $result = $this->ffi->indy_open_pool_ledger($future->getQueueKey(), $configName, $config, [__CLASS__, "openPoolCb"]);
        
        if ($result != 0) {
            throw new LibIndyException(NULL, $result);
        }

        return $future;
    }

    private function stringCb(int $command_handle, int $err, string $json) {
        $queue = \msg_get_queue($command_handle);
        \msg_send($queue, 5, new StringResult($err, $json));
    }

    public function buildGetSchemaRequest(string $submitterDid, string $id) {
        $future = new Future(5);
        $result = $this->ffi->indy_build_get_schema_request($future->getQueueKey(), $submitterDid, $id, [__CLASS__, "stringCb"]);
        
        if ($result != 0) {
            throw new LibIndyException(NULL, $result);
        }

        return $future;
    }

    public function submitRequest(PoolOpenResult $pool, StringResult $requestObject) {
        $future = new Future(5);
        $result = $this->ffi->indy_submit_request($future->getQueueKey(), $pool->getPoolHandle(), $requestObject->getJson(), [__CLASS__, "stringCb"]);
        
        if ($result != 0) {
            throw new LibIndyException(NULL, $result);
        }

        return $future;
    }

    public function parseGetSchemaResponse(StringResult $getSchemaResponse) {
        $future = new Future(1);
        $result = $this->ffi->indy_parse_get_schema_response($future->getQueueKey(), $getSchemaResponse->getJson(), [__CLASS__, "parseResponseCb"]);

        if ($result != 0) {
            throw new LibIndyException(NULL, $result);
        }

        return $future;
    }

    public function buildGetCredDefRequest(string $submitterDid, string $id) {
        $future = new Future(5);
        $result = $this->ffi->indy_build_get_cred_def_request($future->getQueueKey(), $submitterDid, $id, [__CLASS__, "stringCb"]);
        
        if ($result != 0) {
            throw new LibIndyException(NULL, $result);
        }

        return $future;
    }

    public function parseGetCredDefResponse(StringResult $getCredDefResponse) {
        $future = new Future(1);
        $result = $this->ffi->indy_parse_get_cred_def_response($future->getQueueKey(), $getCredDefResponse->getJson(), [__CLASS__, "parseResponseCb"]);

        if ($result != 0) {
            throw new LibIndyException(NULL, $result);
        }

        return $future;
    }

    private function verifyProofCb(int $command_handle, int $err, bool $valid) {
        $queue = \msg_get_queue($command_handle);
        \msg_send($queue, 2, new VerifierResult($err, $valid));
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

class VerifierResult extends BaseResult {
    private $valid;

    function __construct(int $error, bool $valid) {
        parent::__construct($error);
        $this->valid = $valid;
    }

    public function isValid() {
        return $this->valid;
    }
}

class StringResult extends BaseResult {
    private $json;

    function __construct(int $error, string $json) {
        parent::__construct($error);
        $this->json = $json;
    }

    function getJson(): string {
        return $this->json;
    }
}

class ParseResponseResult extends BaseResult {
    private $id;
    private $json;

    function __construct(int $error, string $id, string $json) {
        parent::__construct($error);
        $this->id = $id;
        $this->json = $json;
    }

    function getId() {
        return $this->id;
    }

    function getJson() {
        return $this->json;
    }
}

class PoolOpenResult extends BaseResult {
    private $poolHandle;

    function __construct(int $error, int $poolHandle) {
        parent::__construct($error);
        $this->poolHandle = $poolHandle;
    }

    function getPoolHandle() {
        return $this->poolHandle;
    }
}

class Future {
    private $queue;
    private $q_key;
    private $msg_type;
    public ?BaseResult $msg;

    function __construct(int $msg_type) {
        $this->msg_type = $msg_type;
        $this->q_key = \random_int(1,999999);
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

class LibIndyException extends \Exception {
    public function __toString() {
        return "LibIndyException code: " . $this->code . " message: " . $this->message;
    }
 }