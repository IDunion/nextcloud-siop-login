<?php

namespace OCA\OIDCLogin\Credentials\Anoncreds;

use OCA\OIDCLogin\LibIndyWrapper\LibIndy;
use OCA\OIDCLogin\LibIndyWrapper\LibIndyException;
use OCA\OIDCLogin\Helper\PresentationExchangeHelper;

use JsonPath\JsonObject;
use OCA\OIDCLogin\LibIndyWrapper\ParseResponseResult;
use OCA\OIDCLogin\LibIndyWrapper\VerifierResult;

class AnoncredHelper
{
    private $credDefHelper;
    private $schemaHelper;
    private $libIndy;
    private $poolHandle;
    private $schema;
    private $credentialPath;

    public function __construct($schemaConfig)
    {
        $this->schemaHelper = new SchemaHelper($schemaConfig);
        $this->libIndy = new LibIndy();

        // for debugging only
        //$this->libIndy->setDefaultLogger("trace");

        $configName = "idunion_test_ledger";
        $config = '{"genesis_txn":"'.__DIR__.'/../../LibIndyWrapper/genesis_txn.txt"}';
        try {
            $this->libIndy->createPoolLedgerConfig($configName, $config)->get();
        } catch (LibIndyException $e) {
            $this->libIndy->deletePoolLedgerConfig($configName)->get();
            $this->libIndy->createPoolLedgerConfig($configName, $config)->get();
        }

        $this->poolHandle = $this->libIndy->openPoolLedger($configName)->get();
    }

    public function close()
    {
        $this->libIndy->closePoolLedger($this->poolHandle)->get();
    }

    public function parseProof(JsonObject $presentationSubmission, string $presentationID, string $vpToken)
    {
        $jsonProof = new JsonObject($vpToken, true);
        $credDefId = $jsonProof->get('$.identifiers[0].cred_def_id');
        $this->credDefHelper = new CredDefHelper($credDefId);
        $this->credentialPath = PresentationExchangeHelper::parsePresentationSubmission($presentationSubmission, $presentationID);
    }

    public function getCredDef(): ParseResponseResult
    {
        // TODO get DID and ID from CredDefHelper
        $credDefRequest = $this->libIndy->buildGetCredDefRequest($this->credDefHelper->getCredentialDID(), $this->credDefHelper->getCredentialId())->get();
        $credDefResponseRaw = $this->libIndy->submitRequest($this->poolHandle, $credDefRequest)->get();
        return $this->libIndy->parseGetCredDefResponse($credDefResponseRaw)->get();
    }

    public function getSchema(): ParseResponseResult
    {
        if (empty($this->schema)) {
            $schemaRequest = $this->libIndy->buildGetSchemaRequest(
                $this->schemaHelper->getSchemaDID(),
                $this->schemaHelper->getSchemaIdForIndy()
            )->get();
            $schemaResponseRaw = $this->libIndy->submitRequest($this->poolHandle, $schemaRequest)->get();
            $this->schema = $this->libIndy->parseGetSchemaResponse($schemaResponseRaw)->get();
        }
        return $this->schema;
    }

    public function verifyProof($vpTokenRaw, $nonce, $presentationID, $schemaConfig, $logger): VerifierResult {
        $schemaAttr = $this->getSchemaAttributes();
        $proofRequest = PresentationExchangeHelper::createProofRequest($nonce, $schemaConfig, $schemaAttr, $presentationID);
        
        $logger->debug('Anoncred proof request: ' . $proofRequest);
        
        $schemaResponse = $this->getSchema();
        $schemas = json_encode(array(
            $schemaResponse->getId() => json_decode($schemaResponse->getJson())
        ));
        $logger->debug('Anoncred verification - schemas: ' . $schemas);
        $credDefResponse = $this->getCredDef();
        $credentials = json_encode(array(
            $credDefResponse->getId() => json_decode($credDefResponse->getJson())
        ));
        $logger->debug('Anoncred verification - credentials: ' . $credentials);

        return $this->libIndy->verifierVerifyProof($proofRequest, $vpTokenRaw, $schemas, $credentials, "{}", "{}")->get();
    }

    public function getSchemaAttributes(): array
    {
        $schema = $this->getSchema();
        $jsonSchema = new JsonObject($schema->getJson(), true);
        return $jsonSchema->get('$.attrNames');
    }

    public function getAttributesFromProof(string $vpToken): array
    {
        $jsonVP = new JsonObject($vpToken, true);
        $result = array();
        foreach ($this->getSchemaAttributes() as $attr) {
            if (in_array($attr, $this->schemaHelper->getSchemaDesiredAttr())) {
                $result[$attr] = $jsonVP->get($this->credentialPath.'.values.'.$attr.'.raw');
            }
        }
        return $result;
    }

    public function getEncoding($value)
    {
        if (empty($value)) {
            $value = '';
        } elseif (is_integer($value)) {
            $value = strval($value);
        }
    
        $hex = hash('sha256', utf8_encode($value), false);
        $bigInt = gmp_init($hex, 16);
        return gmp_strval($bigInt);
    }

    public function verifyAttributes(string $vpToken): bool
    {
        $jsonVP = new JsonObject($vpToken, true);
        foreach ($this->getSchemaAttributes() as $attr) {
            if (in_array($attr, $this->schemaHelper->getSchemaDesiredAttr())) {
                $attrRaw = $jsonVP->get($this->credentialPath.'.values.'.$attr.'.raw');
                $attrEncoded = $jsonVP->get($this->credentialPath.'.values.'.$attr.'.encoded');
                $attrEncodedProof = $jsonVP->get('$.proof.proofs[0].primary_proof.eq_proof.revealed_attrs.'.$attr);
                if ($this->getEncoding($attrRaw) != $attrEncoded || $this->getEncoding($attrRaw) != $attrEncodedProof) {
                    return false;
                }
            }
        }
        return true;
    }
}
