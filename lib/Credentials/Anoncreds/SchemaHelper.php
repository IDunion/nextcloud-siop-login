<?php

namespace OCA\OIDCLogin\Credentials\Anoncreds;

class SchemaHelper {
    private $schemaDID;
    private $schemaIdForIndy;
    private $schemaIdFull;
    private $schemaVersion;
    private $schemaDesiredAttr;

    function __construct($schemaConfig) {
        $schemaId = array_keys($schemaConfig)[0];
        $this->schemaDesiredAttr = $schemaConfig[$schemaId];
        $schemaIdParts = explode(":", $schemaId);
        if (str_starts_with($schemaId, 'did:indy:')) {
            $this->schemaIdForIndy = implode(':', array_slice($schemaIdParts, 4));
            $this->schemaIdFull = $schemaId;
            $this->schemaDID = $schemaIdParts[4];
            $this->schemaVersion = $schemaIdParts[7];        
        } else {
            $this->schemaIdForIndy = $schemaId;
            $this->schemaIdFull = 'did:indy:idu:test:'.$schemaId;
            $this->schemaDID = $schemaIdParts[0];
            $this->schemaVersion = $schemaIdParts[3];            
        }
    }

    /**
     * Get the value of schemaDID
     */
    public function getSchemaDID()
    {
        return $this->schemaDID;
    }

    /**
     * Get the value of schemaIdForIndy
     */
    public function getSchemaIdForIndy()
    {
        return $this->schemaIdForIndy;
    }

    /**
     * Get the value of schemaIdFull
     */
    public function getSchemaIdFull()
    {
        return $this->schemaIdFull;
    }

    /**
     * Get the value of schemaVersion
     */
    public function getSchemaVersion()
    {
        return $this->schemaVersion;
    }

    /**
     * Get the value of schemaDesiredAttr
     */
    public function getSchemaDesiredAttr()
    {
        return $this->schemaDesiredAttr;
    }
}