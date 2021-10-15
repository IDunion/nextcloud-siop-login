<?php

namespace OCA\OIDCLogin\Helper;

class PresentationExchangeHelper {
    private const SCHEMA_REQUIRED = true;
    private const PRESENTATION_DEFINITION_ID = 'NextcloudLogin';
    private const INPUT_DESCRIPTOR0_ID = 'ref2';

    public static function createPresentationDefinition($schemaConfig, $schemaAttr): array {
        $fields = array();
        $sHelper = new SchemaHelper($schemaConfig);
        $desiredAttr = $sHelper->getSchemaDesiredAttr();
        foreach($schemaAttr as $attr) {
            if(in_array($attr, $desiredAttr) || empty($desiredAttr)) {
                array_push($fields, array('path' => array('$.values.'.$attr)));
            }
        }

        return array(
            'presentation_definition' => array(
                'id' => PresentationExchangeHelper::PRESENTATION_DEFINITION_ID,
                'input_descriptors' => array(
                    array(
                        'id' => PresentationExchangeHelper::INPUT_DESCRIPTOR0_ID,
                        'name' => 'NextcloudCredential',
                        'schema' => array(
                            array(
                                'uri' => $sHelper->getSchemaIdFull(), 
                                'required' => PresentationExchangeHelper::SCHEMA_REQUIRED,
                            ),
                        ),
                        'constraints' => array(
                            'limit_disclosure' => 'required',
                            'fields' => $fields,
                        ),
                    ),
                ),
            ),
        );
    }

    public static function createProofRequest($nonce, $schemaConfig, $schemaAttr): string {
        $schemaHelper = new SchemaHelper($schemaConfig);
        $attrs = array();
        foreach($schemaAttr as $attr) {
            if(in_array($attr, $schemaHelper->getSchemaDesiredAttr()) 
            || empty($schemaHelper->getSchemaDesiredAttr())) {
                array_push($attrs, $attr);
            }
        }

        $requestedAttributes0 = array(
            PresentationExchangeHelper::INPUT_DESCRIPTOR0_ID => array(
                "names" => array("first_name", "last_name", "email"),
            )
        );
        
        if (PresentationExchangeHelper::SCHEMA_REQUIRED) {
            $requestedAttributes0[PresentationExchangeHelper::INPUT_DESCRIPTOR0_ID]["restrictions"] = array(array("schema_id" => $schemaHelper->getSchemaIdForIndy()));
        }        

        return json_encode(
            array(
                "nonce" => $nonce,
                "name" => PresentationExchangeHelper::PRESENTATION_DEFINITION_ID,
                "version" => $schemaHelper->getSchemaVersion(),
                "requested_attributes" => $requestedAttributes0 
            )
        );
    }
}