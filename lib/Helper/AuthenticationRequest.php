<?php

namespace OCA\OIDCLogin\Helper;

use OCA\OIDCLogin\Db\RequestObject;
use OCA\OIDCLogin\Credentials\Anoncreds\AnoncredHelper;

use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

class AuthenticationRequest
{
    private $appName;
    private $urlGenerator;
    private $timeFactory;
    private $config;
    private $requestObjectMapper;
    private $nonce;

    private $presentationDefinition;
    private $registration = Null;

    public function __construct($appName, $urlGenerator, $timeFactory, $config, $requestObjectMapper, $nonce, $presentationID, $logger)
    {
        $this->appName = $appName;
        $this->urlGenerator = $urlGenerator;
        $this->timeFactory = $timeFactory;
        $this->config = $config;
        $this->requestObjectMapper = $requestObjectMapper;
        $this->nonce = $nonce;
        
        if ($this->config->getSystemValue('oidc_login_use_sd_jwt', false)) {
            $this->presentationDefinition = SdJwtPresentationExchangeHelper::createPresentationDefinition($presentationID);
        } else {
            $schemaConfig = $this->config->getSystemValue('oidc_login_anoncred_config', array());
            $acHelper = new AnoncredHelper($schemaConfig);
            $schemaAttr = $acHelper->getSchemaAttributes();
            $acHelper->close();
            $jsonldConfig = $this->config->getSystemValue('oidc_login_jsonld_config', array());
            $this->presentationDefinition = PresentationExchangeHelper::createPresentationDefinition(
                                                    $schemaConfig,
                                                    $schemaAttr,
                                                    $jsonldConfig,
                                                    $presentationID
                                                );

            $this->registration = array(
                'vp_formats' => array(
                    'ac_vp' => array(
                        'proof_type' => array('CLSignature2019')
                    ),
                    'ldp_vc' => array(
                        'proof_type' => array('BbsBlsSignature2020')
                    ),
                    'ldp_vp' => array(
                        'proof_type' => array('BbsBlsSignature2020')
                    ),
                ),
            );
        }
    }

    public function createOnDevice(): string
    {
        $redirectUri = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.callback');
        $useRequestUri = $this->config->getSystemValue('oidc_login_use_request_uri', true);
        return $this->createAuthenticationRequest($redirectUri, $useRequestUri);
    }

    public function createCrossDevice(): string
    {
        $redirectUri = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.callback');
        $useRequestUri = $this->config->getSystemValue('oidc_login_use_request_uri', true);
        return $this->createAuthenticationRequest($redirectUri, $useRequestUri, 'direct_post');
    }

    private function createAuthenticationRequest($redirectUri, $useRequestUri, $responseMode = null): string
    {
        $schema = $this->config->getSystemValue('oidc_login_request_domain', 'openid://');

        $arData = array(
            'response_type' => 'vp_token',
            'client_id' => $redirectUri,
            'redirect_uri' => $redirectUri,         
            'nonce' => $this->nonce
        );

        if (!empty($responseMode)) {
            $arData['response_mode'] = $responseMode;
        }
        
        if ($useRequestUri) {
            $arData['presentation_definition'] = $this->presentationDefinition;
            if (!is_null($this->registration)) {
                $arData['registration'] = $this->registration;
            }

            // Create request object as JWT signed with the none algorithm
            $algorithmManager = new AlgorithmManager([new None()]);
            $jwk = JWKFactory::createNoneKey();
            $jwsBuilder = new JWSBuilder($algorithmManager);
            $jws = $jwsBuilder
                        ->create()
                        ->withPayload(json_encode($arData))
                        ->addSignature($jwk, ['alg' => 'none'])
                        ->build();
            $serializer = new CompactSerializer();
            $token = $serializer->serialize($jws, 0);
 
            // Create request_uri with a random id
            $requestUri = $this->urlGenerator->linkToRouteAbsolute(
                $this->appName.'.login.requestObject', 
                array('id' => bin2hex(random_bytes(16)))
            );

            // Save request object to the database
            $requestObject = new RequestObject();
            $requestObject->setRequestUri($requestUri);
            $requestObject->setRequestObject($token);
            $requestObject->setCreationTimestamp($this->timeFactory->getTime());
            $this->requestObjectMapper->insert($requestObject);

            // After JAR specification
            $arDataRequestUri['client_id'] = $redirectUri;
            $arDataRequestUri['request_uri'] = $requestUri;
            return $schema . "?" . http_build_query($arDataRequestUri);
        } else {
            $arData['presentation_definition'] = json_encode($this->presentationDefinition);
            $arData['registration'] = json_encode($this->registration);

            return $schema . "?" . http_build_query($arData);
        }
    }
}
