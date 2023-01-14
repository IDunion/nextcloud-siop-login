<?php

namespace OCA\OIDCLogin\Credentials\W3CVerifiableCredentials;

use OC\User\LoginException;

use JsonPath\JsonObject;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use OCA\OIDCLogin\Helper\PresentationExchangeHelper;

class VCVerifier {
    public static function verify(string $vpTokenRaw, JsonObject $presentationSubmission, string $presentationSubmissionID, string $nonce, array $jsonLDConfig, $logger): array {
        $logger->debug('Processing W3C Verifiable Credential');
        $vpToken = new JsonObject($vpTokenRaw, true);

        // Check whether the presentation submission has the expected format and values
        if (!VCVerifier::verifyPresentationSubmission($presentationSubmission, $presentationSubmissionID)) {
            $logger->error('Presentation submission has an unexpected format or contains wrong values: '.$presentationSubmission->getJson());
            throw new LoginException('Presentation submission has an unexpected format or contains wrong values.');
        }

        // Extract presentation and credential from vp_token
        $presentation = $vpToken->getJsonObjects($presentationSubmission->get('$.descriptor_map[0].path'));
        $credential = $presentation->getJsonObjects($presentationSubmission->get('$.descriptor_map[0].path_nested.path'));

        // Check if nonce is correct
        // TODO uncomment lines below to check the nonce
        $nonce = "challenge";
        
        if ($presentation->get('$.proof.challenge') != $nonce) {
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
        $client = new Client(['base_uri' => $jsonLDConfig['verifier_uri']]);
        $headers = [
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $jsonLDConfig['verifier_access_token']
            ];
        $body = array(
            "credential" => $presentation->getValue(),
            "challenge" => $nonce,
        );
        $request = new Request('POST', '/w3c/verification', $headers, json_encode($body));
        $response = $client->send($request);
        $jsonResponse = json_decode($response->getBody());

        if (!$jsonResponse->verified) {
            $logger->error('Could not verify W3C Credential: Invalid signature or schema');
            throw new LoginException('Could not verify W3C Credential: Invalid signature or schema');
        }

        // Get user claims from credential
        foreach ($jsonLDConfig['claims'] as $claim) {
            $profile[$claim] = $credential->get('$.credentialSubject.' . $claim);
        }
        return $profile;
    }

    private static function verifyPresentationSubmission(JsonObject $ps, string $presentationSubmissionID): bool {
        if ($ps->get('$.definition_id') != $presentationSubmissionID) {
            return false;
        }

        if (count($ps->get('$.descriptor_map')) != 1) {
            return false;
        }

        if ($ps->get('$.descriptor_map[0].id') != PresentationExchangeHelper::INPUT_DESCRIPTOR1_ID) {
            return false;
        }

        if ($ps->get('$.descriptor_map[0].format') != "ldp_vp") {
            return false;
        }

        if ($ps->get('$.descriptor_map[0].path_nested.id') != PresentationExchangeHelper::INPUT_DESCRIPTOR1_ID) {
            return false;
        }

        if ($ps->get('$.descriptor_map[0].path_nested.format') != 'ldp_vc') {
            return false;
        }

        return true;
    }
}