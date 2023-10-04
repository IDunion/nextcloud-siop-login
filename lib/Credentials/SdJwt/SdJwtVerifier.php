<?php

namespace OCA\OIDCLogin\Credentials\SdJwt;

use OC\User\LoginException;

use JsonPath\JsonObject;
use idunion\sdjwt\SDJWT;
use OCA\OIDCLogin\Helper\SdJwtPresentationExchangeHelper;


class SdJwtVerifier {
    public static function verify(string $vpTokenRaw, JsonObject $presentationSubmission, string $presentationSubmissionID, string $nonce, string $redirectUri, array $sdJwtConfig, $logger): array {
        if (!SdJwtVerifier::verifyPresentationSubmission($presentationSubmission, $presentationSubmissionID)) {
            $logger->error('Presentation submission has an unexpected format or contains wrong values: '.$presentationSubmission->getJson());
            throw new LoginException('Presentation submission has an unexpected format or contains wrong values.');
        }
        $holder_binding = FALSE;
        if (array_key_exists('holder_binding', $sdJwtConfig)) {
            $holder_binding = $sdJwtConfig['holder_binding'];
        }
        $status_list = FALSE;
        if (array_key_exists('status_list', $sdJwtConfig)) {
            $status_list = $sdJwtConfig['status_list'];
        }

        $getIssuerCallback = new GetIssuerKey($sdJwtConfig['trusted_issuers'], $logger);
        $userClaims = SDJWT::decode($vpTokenRaw, $getIssuerCallback, $redirectUri, $nonce, $holder_binding, $status_list);
        $profile["email"] = $userClaims->email;
        
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

        if ($ps->get('$.descriptor_map[0].format') != 'vc+sd-jwt') {
            return false;
        }

        if ($ps->get('$.descriptor_map[0].path') != '$') {
            return false;
        }

        return true;
    }
}

class GetIssuerKey {
    /** @var array */
    private $trusted_issuers;
    private $logger;

    function __construct(array $trusted_issuers, $logger) {
        $this->trusted_issuers = $trusted_issuers;
        $this->logger = $logger;
    }

    public function __invoke(string $issuer, string $kid): string {
        $this->logger->debug('getkey: ' . $issuer . " -> " . json_encode($kid));
        // check if in trusted_issuers
        if (!$this->is_trusted($issuer)) {
            throw new LoginException('issuer is not trusted');
        }

        // Switch depending on prefix
        if (str_starts_with($issuer, "did:jwk")) {
            return $this->did_jwk($issuer);
        }
        if (str_starts_with($issuer, "https://")) {
            return $this->web($issuer, $kid);
        }
    }

    private function is_trusted($issuer): bool {
        // remove trailing slash if https is used
        if (str_starts_with($issuer, "https://")) {
            $issuer = rtrim($issuer, "/");
        }
        return in_array( $issuer, $this->trusted_issuers);
    }

    private function did_jwk($issuer): string {
        $parts = explode(":", $issuer);
        // expect did:jwk:1234
        return base64_decode($parts[2]);
    }

    // get issuer/.well-known/jwt-issuer
    // follow jwks_uri if it exists
    private function web(string $issuer, string $kid): string {
        $issuer = rtrim($issuer, "/");
        $url = $issuer . "/.well-known/jwt-issuer";
        $content = file_get_contents($url);
        $decoded = json_decode($content, false);
        // check if jwks is present or we have to follow the jwks_uri
        if (isset($decoded->jwks)) {
            $jwks = $decoded->jwks;
        } else {
            $jwks_raw = file_get_contents($decoded->jwks_uri);
            $jwks = json_decode($jwks_raw, false);
            if (!$jwks) {
                throw new LoginException('could not decode jwks');
            }
        }
        // walk the jwks and find correct kid
        foreach ($jwks->keys as $key){
            if ($key->kid == $kid) {
                return json_encode($key);
            }
        }
        throw new LoginException('kid not found at /.well-known/jwt-issuer');
    }
}
