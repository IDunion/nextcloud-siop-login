<?php

namespace OCA\OIDCLogin\Helper;

use Exception;
use JsonPath\JsonObject;

class SdJwtPresentationExchangeHelper {
    public const INPUT_DESCRIPTOR_ID = 'NextcloudCredential';

    public static function createPresentationDefinition($presentationID): array {
        return array(
            "id" => $presentationID,
            "input_descriptors" => array(
                array(
                    "id" => SdJwtPresentationExchangeHelper::INPUT_DESCRIPTOR_ID,
                    "format" => array(
                        "vc+sd-jwt" => array(
                            "proof_type" => array("JsonWebSignature2020")
                        )
                    ),
                    "constraints" => array(
                        "limit_disclosure" => "required",
                        "fields" => array(
                            array(
                                "path" => array("$.vct"),
                                "filter" => array(
                                    "type" => "string",
                                    "const" => "https://credentials.idunion.org/VerifiedEMail"
                                )
                            ),
                            array(
                                "path" => array("$.email")
                            )
                        )
                    )
                )
            )
        );
    }
}
