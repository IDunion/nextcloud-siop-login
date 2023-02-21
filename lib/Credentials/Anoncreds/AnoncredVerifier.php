<?php

namespace OCA\OIDCLogin\Credentials\Anoncreds;

use JsonPath\JsonObject;
use OC\User\LoginException;

class AnoncredVerifier {
    public static function verify(string $vpTokenRaw, JsonObject $presentationSubmission, $schemaConfig, string $nonce, string $presentationID, $logger): array {
        $logger->debug('Processing Anoncred Credential');
        $acHelper = new AnoncredHelper($schemaConfig);
        $acHelper->parseProof($presentationSubmission, $presentationID, $vpTokenRaw);
        if (!$acHelper->verifyAttributes($vpTokenRaw)) {
            $acHelper->close();
            throw new LoginException('The credential attributes have been manipulated');
        }

        // Verify the signature of the Anoncred proof
        $valid = $acHelper->verifyProof($vpTokenRaw, $nonce, $schemaConfig, $logger);

        if (!$valid->isValid()) {
            $acHelper->close();
            throw new LoginException("Credential verification failed");
        }
        $logger->debug('Successfully verified Anoncred proof');

        // get attributes from proof
        $profile = $acHelper->getAttributesFromProof($vpTokenRaw);

        $acHelper->close();

        return $profile;
    }
}