<?php

namespace OCA\OIDCLogin\Credentials\W3CVerifiableCredentials;

use OC\User\LoginException;

use JsonPath\JsonObject;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use OCA\OIDCLogin\Helper\PresentationExchangeHelper;

class VCVerifier {
    public static function verify(string $vpTokenRaw, JsonObject $presentationSubmission, string $nonce, array $jsonLDConfig, $logger): array {
        $logger->debug('Processing W3C Verifiable Credential');
        $vpToken = new JsonObject($vpTokenRaw, true);

        // Check whether the presentation submission has the expected format and values
        if (!VCVerifier::verifyPresentationSubmission($presentationSubmission)) {
            $logger->warning('Presentation Submission has an unexpected format or contains unexpected values: '.$presentationSubmission->getJson());
        }

        // Extract presentation and credential from vp_token
        $presentation = $vpToken->getJsonObjects($presentationSubmission->get('$.presentation_submission.descriptor_map[0].path'));
        $credential = $presentation->getJsonObjects($presentationSubmission->get('$.presentation_submission.descriptor_map[0].path_nested.path'));

        // Check if nonce is correct
        if ($credential->get('$.proof.nonce') != $nonce) {
            $logger->error('Could not verify W3C Credential: Wrong nonce');
            throw new LoginException('Could not verify W3C Credential: Wrong nonce');
        }

        // Check if the credential has the correct type
        $typeConfigured = $jsonLDConfig['type'];
        $typeFound = $credential->get('$.type');
        if (!(count($typeFound) == count($typeConfigured) && !array_diff($typeFound, $typeConfigured))) {
            $logger->error('Could not verify W3C Credential: Wrong type');
            throw new LoginException('Could not verify W3C Credential: Wrong type');
        }

        // Send presentation to verification service
        // TODO remove comments
        /*$client = new Client(['base_uri' => $jsonLDConfig['verifier_uri']]);
        $headers = [
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $jsonLDConfig['verifier_access_token']
            ];
        $request = new Request('POST', '/w3c/verification', $headers, $presentation->getJson());
        $response = $client->send($request);
        $jsonResponse = json_decode($response->getBody());

        if (!$jsonResponse->verified) {
            $logger->error('Could not verify W3C Credential: Invalid signature or schema');
            throw new LoginException('Could not verify W3C Credential: Invalid signature or schema');
        }*/

        // Get user claims from credential
        foreach ($jsonLDConfig['claims'] as $claim) {
            $profile[$claim] = $credential->get('$.credentialSubject.' . $claim);
        }
        return $profile;
    }

    private static function verifyPresentationSubmission(JsonObject $ps): bool {
        if (count($ps->get('$.presentation_submission.descriptor_map')) != 1) {
            return false;
        }

        if ($ps->get('$.presentation_submission.descriptor_map[0].id') != PresentationExchangeHelper::INPUT_DESCRIPTOR1_ID) {
            return false;
        }

        if ($ps->get('$.presentation_submission.descriptor_map[0].format') != "ldp_vp") {
            return false;
        }

        if ($ps->get('$.presentation_submission.descriptor_map[0].path_nested.id') != PresentationExchangeHelper::INPUT_DESCRIPTOR1_ID) {
            return false;
        }

        if ($ps->get('$.presentation_submission.descriptor_map[0].path_nested.format') != 'ldp_vc') {
            return false;
        }

        return true;
    }
}