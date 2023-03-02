<?php

namespace idunion\sdjwt;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use stdClass;
use UnexpectedValueException;
use Map;
use PhpParser\Node\Expr\Cast\Bool_;
use Traversable;

final class SDJWT
{
    private const SEPARATOR_SD = "~";
    private const SEPARATOR_JWT = ".";

    private const SD_CLAIM = "_sd";
    private const SUPPORTED_SD_ALGS = [
        'sha-256' => 'sha256',
    ];

    // decodes input string
    // expects callback get_issuer_key that resolves from string issuer to issuer pubkey
    public static function decode(string $raw, $get_issuer_key, string $expected_audience, string $nonce, ?bool $expect_holderbinding = TRUE): mixed
    {
        // split input and validate jwts
        $output = static::split($raw, $get_issuer_key, $expect_holderbinding);

        if ($expect_holderbinding) {
            // Check for expected audience
            if (!isset($output->proof_of_posession->aud)) {
                throw new UnexpectedValueException('Audience missing in jwt');
            }
            if ($output->proof_of_posession->aud != $expected_audience) {
                throw new UnexpectedValueException('Expected audience does not match');
            }

            // Check for expected nonce
            if (!isset($output->proof_of_posession->nonce)) {
                throw new UnexpectedValueException('nonce missing in jwt');
            }
            if ($output->proof_of_posession->nonce != $nonce) {
                throw new UnexpectedValueException('Expected nonce does not match');
            }
        }

        // Get _sd_alg to hash the disclosed elements
        if (!isset($output->jwt->_sd_alg)) {
            throw new UnexpectedValueException('_sd_alg missing in jwt');
        }
        $sd_alg = strtolower($output->jwt->_sd_alg);
        if (!array_key_exists($sd_alg, self::SUPPORTED_SD_ALGS)) {
            throw new UnexpectedValueException('_sd_alg not supported: ' . $sd_alg);
        }
        $sd_alg = self::SUPPORTED_SD_ALGS[$sd_alg];
        $sd_claims = [];
        // Iterate through sd claims and create map of hashes and values
        foreach ($output->sdclaims as $value) {
            $hash_value =  static::base64_encode_urlsafe(hash($sd_alg, $value, true));
            $attributes = json_decode(static::base64_decode_urlsafe($value), false);
            if ($attributes == false) {
                throw new UnexpectedValueException('unable to decode base64');
            }
            $sd_claims[$hash_value] = $attributes;
        }
        $sd_claims_pointer = &$sd_claims;
        $jwt = &$output->jwt;
        $sd_claims_pointer = self::walk($jwt, $sd_claims_pointer);
        // Check if all claims were used and return false if not
        if(!empty($sd_claims_pointer)) {
            throw new UnexpectedValueException('Could not resolve all claims');
        }
        return $jwt;
    }

    // walks over the jwt and resolves claims and _sd elements
    public static function walk($object, $claims): array
    {
        foreach ($object as $key => $value) {
            if ($key == self::SD_CLAIM) {
                if (!is_array($value)) {
                    throw new UnexpectedValueException('_sd is not an array');
                }
                //check for hashes in disclosures
                foreach ($value as $hash) {
                    if (isset($claims[$hash])) {
                        $attribute_name = $claims[$hash][1];
                        $attribute_value = $claims[$hash][2];
                        $object->$attribute_name = $attribute_value;
                        unset($claims[$hash]);
                    }
                }
                unset($object->$key);
            } else {
                if(is_object($object)) {
                    $ptr = &$object->$key;
                } elseif (is_array($object)) {
                    $ptr = &$object[$key];
                }
                if (is_array($ptr) || is_object($ptr) ||  $ptr instanceof Traversable) {
                    $claims = self::walk($ptr, $claims);
                }
            }
        }
        return $claims;
    }

    public static function split(string $raw, $get_issuer_key, bool $expect_holderbinding = TRUE): SDJWT_Components
    {
        // Expand by separator
        $out = explode(self::SEPARATOR_SD, $raw);
        $jwt_raw = array_shift($out);
        $proof_of_posession = array_pop($out);
        $sd_claims = $out;

        // manually extract issuer from jwt
        $out = explode(self::SEPARATOR_JWT, $jwt_raw);
        if (count($out) < 2) {
            throw new UnexpectedValueException('Unexpected Format of JWT, expected more elements');
        }
        // convert from urlsafe base64 to base64
        $jwt = static::base64_to_jwt($out[1]);
        if ($jwt == false) {
            throw new UnexpectedValueException('Could not decode jwt');
        }

        if (!isset($jwt['iss'])) {
            throw new UnexpectedValueException('Issuer is missing from JWT');
        }
        $iss = $jwt['iss'];
        // call the callback to resolve the issuer key (in JWK string format)
        $issuer_key_raw = call_user_func($get_issuer_key, $iss);
        if ($issuer_key_raw == null || $issuer_key_raw == "") {
            throw new UnexpectedValueException('Issuer key does not exist');
        }
        $issuer_key = json_decode($issuer_key_raw, true, 512, JSON_BIGINT_AS_STRING);
        $issuer_jwk = JWK::parseKey($issuer_key, "ES256");

        $output = new SDJWT_Components();

        if ($expect_holderbinding) {
            // get the cnf element to find the holder binding
            if (!isset($jwt['cnf'])) {
                throw new UnexpectedValueException('holder binding is missing from JWT');
            }
            $holder_key = $jwt['cnf']['jwk'];
            $holder_jwk = JWK::parseKey($holder_key, "ES256");
            $output->proof_of_posession = JWT::decode($proof_of_posession, $holder_jwk);
        }

        $output->jwt = JWT::decode($jwt_raw, $issuer_jwk);
        $output->sdclaims = $sd_claims;

        return $output;
    }

    private static function base64_to_jwt(string $raw): mixed
    {
        $raw = static::base64_decode_urlsafe($raw);
        if ($raw == false) {
            return false;
        }
        return json_decode($raw, true, 512, JSON_BIGINT_AS_STRING);
    }

    private static function base64_decode_urlsafe(string $raw): string | false
    {
        $raw = str_replace("_", "/", $raw);
        $raw = str_replace("-", "+", $raw);
        $padding = strlen($raw) % 4;
        if ($padding > 0) {
            $raw .= str_repeat("=", $padding);
        }
        return base64_decode($raw);
    }

    private static function base64_encode_urlsafe(string $raw): string
    {
        $raw = base64_encode($raw);
        $raw = str_replace("+", "-", $raw);
        $raw = str_replace("/", "_", $raw);
        $raw = str_replace("=", "", $raw);
        return $raw;
    }
}

final class SDJWT_Components
{
    public stdClass $jwt;
    public $sdclaims = array();
    public stdClass $proof_of_posession;
}
