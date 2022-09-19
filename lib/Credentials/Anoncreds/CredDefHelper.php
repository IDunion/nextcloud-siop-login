<?php

namespace OCA\OIDCLogin\Credentials\Anoncreds;

class CredDefHelper {
    private $credentialId;
    private $credentialDID;

    function __construct(string $credentialId) {
        $this->credentialId = $credentialId;
        $credentialIdParts = explode(':', $this->credentialId);
        $this->credentialDID = $credentialIdParts[0];        
    }

    /**
     * Get the value of credentialId
     */
    public function getCredentialId()
    {
        return $this->credentialId;
    }

    /**
     * Get the value of credentialDID
     */
    public function getCredentialDID()
    {
        return $this->credentialDID;
    }
}