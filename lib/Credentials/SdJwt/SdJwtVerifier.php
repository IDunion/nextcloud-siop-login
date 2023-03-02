<?php

namespace OCA\OIDCLogin\Credentials\SdJwt;

use OC\User\LoginException;

use JsonPath\JsonObject;
use idunion\sdjwt\SDJWT;
use OCA\OIDCLogin\Helper\SdJwtPresentationExchangeHelper;


class SdJwtVerifier {
    public static function verify(string $vpTokenRaw, JsonObject $presentationSubmission, string $presentationSubmissionID, string $nonce, string $redirectUri, $logger): array {
        if (!SdJwtVerifier::verifyPresentationSubmission($presentationSubmission, $presentationSubmissionID)) {
            $logger->error('Presentation submission has an unexpected format or contains wrong values: '.$presentationSubmission->getJson());
            throw new LoginException('Presentation submission has an unexpected format or contains wrong values.');
        }

        $getIssuerCallback = new GetIssuerKey();
        $userClaims = SDJWT::decode($vpTokenRaw, $getIssuerCallback, $redirectUri, $nonce, FALSE);
        $profile["email"] = $userClaims->credentialSubject->email;
        
        return $profile;
    }

    

    private static function verifyPresentationSubmission(JsonObject $ps, string $presentationSubmissionID): bool {
        if ($ps->get('$.definition_id') != $presentationSubmissionID) {
            return false;
        }

        if (count($ps->get('$.descriptor_map')) != 1) {
            return false;
        }

        if ($ps->get('$.descriptor_map[0].id') != SdJwtPresentationExchangeHelper::INPUT_DESCRIPTOR_ID) {
            return false;
        }

        if ($ps->get('$.descriptor_map[0].format') != 'vp+sd-jwt') {
            return false;
        }

        if ($ps->get('$.descriptor_map[0].path') != '$') {
            return false;
        }

        return true;
    }
}

class GetIssuerKey {
    public function __invoke($issuer) {
        // Assume $issuer is a DID JWK
        $parts = explode(":", $issuer);
        return base64_decode($parts[2]);
    }
}