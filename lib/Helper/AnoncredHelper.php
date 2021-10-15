<?php

namespace OCA\OIDCLogin\Helper;

use OCA\OIDCLogin\LibIndyWrapper\LibIndy;
use OCA\OIDCLogin\LibIndyWrapper\LibIndyException;

use JsonPath\JsonObject;
use OCA\OIDCLogin\LibIndyWrapper\ParseResponseResult;

class AnoncredHelper {
    private $credDefId;
    private $schemaHelper;
    private $libIndy;
    private $poolHandle;
    private $schema;

    function __construct($schemaConfig) {
        $this->schemaHelper = new SchemaHelper($schemaConfig);
        $this->libIndy = new LibIndy();

        $configName = "idunion_test_ledger";
        $config = '{"genesis_txn":"'.__DIR__.'/../LibIndyWrapper/genesis_txn.txt"}';
        try {
            $this->libIndy->createPoolLedgerConfig($configName, $config)->get();
        } catch (LibIndyException $e) {
            $this->libIndy->deletePoolLedgerConfig($configName)->get();
            $this->libIndy->createPoolLedgerConfig($configName, $config)->get();
        }

        $this->poolHandle = $this->libIndy->openPoolLedger($configName)->get();
    }

    public function parseProof(string $anoncredProof) {
        $jsonProof = new JsonObject($anoncredProof, true);
        $this->credDefId = $jsonProof->get('$.identifiers[0].cred_def_id');
    }

    public function getCredDef(): ParseResponseResult {
        $credDefRequest = $this->libIndy->buildGetCredDefRequest("CsiDLAiFkQb9N4NDJKUagd", "CsiDLAiFkQb9N4NDJKUagd:3:CL:4687:NextcloudPrototypeCredentialWithoutRev")->get();
        $credDefResponseRaw = $this->libIndy->submitRequest($this->poolHandle, $credDefRequest)->get();
        return $this->libIndy->parseGetCredDefResponse($credDefResponseRaw)->get();
    }

    /**
     * Get the value of credDefId
     */
    public function getCredDefId()
    {
        return $this->credDefId;
    }

    public function getSchema(): ParseResponseResult {
        if(empty($this->schema)) {
            $schemaRequest = $this->libIndy->buildGetSchemaRequest(
                $this->schemaHelper->getSchemaDID(),
                $this->schemaHelper->getSchemaIdForIndy()
            )->get();
            $schemaResponseRaw = $this->libIndy->submitRequest($this->poolHandle, $schemaRequest)->get();
            $this->schema = $this->libIndy->parseGetSchemaResponse($schemaResponseRaw)->get();
        }
        return $this->schema;
    }

    public function getSchemaAttributes(): array {
        $schema = $this->getSchema();
        $jsonSchema = new JsonObject($schema->getJson(), true);
        return $jsonSchema->get('$.attrNames');
    }

}