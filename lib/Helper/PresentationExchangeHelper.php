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

    public static function createPresentationDefinition($schemaConfig, $schemaAttr, $jsonldConfig): array {
        return array(
            'id' => PresentationExchangeHelper::PRESENTATION_DEFINITION_ID,
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
        $fields = array(
            array(
                'path' => array('$.schema_id'),
                'filter' => array(
                    'type' => 'string',
                    'const' => $sHelper->getSchemaIdFull()
                )            
            )
        );
        
        $desiredAttr = $sHelper->getSchemaDesiredAttr();
        foreach($schemaAttr as $attr) {
            if(in_array($attr, $desiredAttr) || empty($desiredAttr)) {
                array_push($fields, array('path' => array('$.values.'.$attr)));
            }
        }

        return array(
            'id' => PresentationExchangeHelper::INPUT_DESCRIPTOR0_ID,
            'group' => array('A'),
            'format' => array(
                'ac_vc' => array(
                    'proof_type' => array('CLSignature2019')
                )
            ),
            'constraints' => array(
                'limit_disclosure' => 'required',
                'fields' => $fields,
            )
        );
    }

    private static function jsonldInputDescriptor($jsonldConfig): array {
        $filter = array(
            'type' => 'array',
            'contains' => array('const' => $jsonldConfig['type'])
        );

        $fields = array(
            array(
                'path' => array('$.type'),
                'filter' => $filter
            )
        );

        foreach($jsonldConfig['claims'] as $claim) {
            array_push($fields, array('path' => array('$.credentialSubject.'.$claim)));
        }

        return array(
            'id' => PresentationExchangeHelper::INPUT_DESCRIPTOR1_ID,
            'group' => array('A'),
            'format' => array(
                'ldp_vc' => array(
                    'proof_type' => array('BbsBlsSignature2020')
                ),
                'ldp_vp' => array(
                    'proof_type' => array('BbsBlsSignature2020')
                ),
            ),
            'constraints' => array(
                'limit_disclosure' => 'required',
                'fields' => $fields,
            )
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
                "names" => $attrs,
            )
        );
        
        if (PresentationExchangeHelper::SCHEMA_REQUIRED) {
            $requestedAttributes0[PresentationExchangeHelper::INPUT_DESCRIPTOR0_ID]["restrictions"] = array(array("schema_id" => $schemaHelper->getSchemaIdForIndy()));
        }        

        return json_encode(
            array(
                "nonce" => $nonce,
                "name" => PresentationExchangeHelper::PRESENTATION_DEFINITION_ID,
                "version" => "1.0",
                "requested_attributes" => $requestedAttributes0 
            )
        );
    }

    public static function parsePresentationSubmission(array $presentationSubmission): string {
        $jsonSub = new JsonObject($presentationSubmission, true);
        if ($jsonSub->get('$.presentation_submission.definition_id') 
                != PresentationExchangeHelper::PRESENTATION_DEFINITION_ID) {
            throw new Exception('Presentation submission contains wrong "definition_id"');
        }
        if ($jsonSub->get('$.presentation_submission.descriptor_map[0].format') != 'ac_vp') {
            throw new Exception('Wrong credential format');
        }
        return $jsonSub->get('$.presentation_submission.descriptor_map[0].path_nested.path');
    }
}