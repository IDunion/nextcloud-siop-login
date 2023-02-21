<?php

namespace OCA\OIDCLogin\Helper;

use Exception;
use JsonPath\JsonObject;

use OCA\OIDCLogin\Credentials\Anoncreds\SchemaHelper;

class PresentationExchangeHelper {
    private const SCHEMA_REQUIRED = true;
    private const PRESENTATION_DEFINITION_ID = 'NextcloudCombinedRequest';
    public const INPUT_DESCRIPTOR0_ID = 'NextcloudCredentialAC';
    public const INPUT_DESCRIPTOR1_ID = 'NextcloudCredentialLDP';

    public static function createPresentationDefinition($schemaConfig, $schemaAttr, $jsonldConfig, $presentationID): array {
        return array(
            'id' => $presentationID,
            'submission_requirements' => array(
                array(
                    'name' => 'NextcloudCredential',
                    'rule' => 'pick',
                    'count' => 1,
                    'from' => 'A'
                )
            ),
            'input_descriptors' => array(
                PresentationExchangeHelper::anoncredInputDescriptor($schemaConfig, $schemaAttr),
                PresentationExchangeHelper::jsonldInputDescriptor($jsonldConfig)
            ),
        );
    }

    private static function anoncredInputDescriptor($schemaConfig, $schemaAttr): array {
        $sHelper = new SchemaHelper($schemaConfig);
        $fields = array();
        
        $desiredAttr = $sHelper->getSchemaDesiredAttr();
        foreach($schemaAttr as $attr) {
            if(in_array($attr, $desiredAttr) || empty($desiredAttr)) {
                array_push($fields, array('path' => array('$.values.'.$attr)));
            }
        }

        return array(
            'id' => PresentationExchangeHelper::INPUT_DESCRIPTOR0_ID,
            'group' => array('A'),
            'schema' => array(array('uri' => $sHelper->getSchemaIdFull())),
            'constraints' => array(
                'limit_disclosure' => 'required',
                'fields' => $fields,
            )
        );
    }

    private static function jsonldInputDescriptor($jsonldConfig): array {
        $fields = [];

        foreach($jsonldConfig['claims'] as $claim) {
            array_push($fields, array('path' => array('$.credentialSubject.'.$claim)));
        }

        return array(
            'id' => PresentationExchangeHelper::INPUT_DESCRIPTOR1_ID,
            'group' => array('A'),
            'schema' => array(array('uri' => $jsonldConfig['type'])),
            'constraints' => array(
                'limit_disclosure' => 'required',
                'fields' => $fields,
            )
        );
    }

    public static function createProofRequest($nonce, $schemaConfig, $schemaAttr, $presentationID): string {
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
                "names" => $attrs,
            )
        );
        
        if (PresentationExchangeHelper::SCHEMA_REQUIRED) {
            $requestedAttributes0[PresentationExchangeHelper::INPUT_DESCRIPTOR0_ID]["restrictions"] = array(array("schema_id" => $schemaHelper->getSchemaIdForIndy()));
        }        

        return json_encode(
            array(
                "nonce" => $nonce,
                "name" => $presentationID,
                "version" => "1.0",
                "requested_attributes" => $requestedAttributes0 
            )
        );
    }

    public static function parsePresentationSubmission(JsonObject $presentationSubmission, string $presentationIdFromSession): string {
        if ($presentationSubmission->get('$.definition_id') != $presentationIdFromSession) {
            throw new Exception('Presentation submission contains wrong "definition_id"');
        }
        if ($presentationSubmission->get('$.descriptor_map[0].format') != 'ac_vp') {
            throw new Exception('Wrong credential format');
        }
        return $presentationSubmission->get('$.descriptor_map[0].path_nested.path');
    }
}