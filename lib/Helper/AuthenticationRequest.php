<?php

namespace OCA\OIDCLogin\Helper;

use OCA\OIDCLogin\Db\RequestObject;

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

    private $claims;
    private $registration;

    public function __construct($appName, $urlGenerator, $timeFactory, $config, $requestObjectMapper, $nonce)
    {
        $this->appName = $appName;
        $this->urlGenerator = $urlGenerator;
        $this->timeFactory = $timeFactory;
        $this->config = $config;
        $this->requestObjectMapper = $requestObjectMapper;
        $this->nonce = $nonce;
        
        $schemaConfig = $this->config->getSystemValue('oidc_login_schema_config', array());
        $acHelper = new AnoncredHelper($schemaConfig);
        $schemaAttr = $acHelper->getSchemaAttributes();
        $acHelper->close();
        $this->claims = array(
            'vp_token' => PresentationExchangeHelper::createPresentationDefinition(
                $schemaConfig,
                $schemaAttr
            ),
        );

        $this->registration = array(
            'subject_identifier_types_supported' => array('jkt'),
            'vp_formats' => array('ac_vp' => null),
            'id_token_signing_alg_values_supported' => array('ES384', 'RS256'),
        );
    }

    public function createOnDevice(): string
    {
        $redirectUri = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.callback');
        return $this->createAuthenticationRequest($redirectUri, false);
    }

    public function createCrossDevice(): string
    {
        $redirectUri = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.callback');
        $useRequestUri = $this->config->getSystemValue('oidc_login_use_request_uri', true);
        return $this->createAuthenticationRequest($redirectUri, $useRequestUri, 'post');
    }

    private function createAuthenticationRequest($redirectUri, $useRequestUri, $responseMode = null): string
    {
        $arDataBase = array(
            'response_type' => 'id_token',
            'client_id' => $redirectUri,
            'scope' => 'openid',
        );

        $arDataFull = $arDataBase;
        if (!empty($responseMode)) {
            $arDataFull['response_mode'] = $responseMode;
        }
        $arDataFull['redirect_uri'] = $redirectUri;
        $arDataFull['nonce'] = $this->nonce;
        
        if ($useRequestUri) {
            $arDataFull['claims'] = $this->claims;
            $arDataFull['registration'] = $this->registration;

            // Create request object as JWT signed with the none algorithm
            $algorithmManager = new AlgorithmManager([new None()]);
            $jwk = JWKFactory::createNoneKey();
            $jwsBuilder = new JWSBuilder($algorithmManager);
            $jws = $jwsBuilder
                        ->create()
                        ->withPayload(json_encode($arDataFull))
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

            // Create authentication request with redirect_uri and parameters after:
            // https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
            $arDataRequestUri = $arDataBase;
            $arDataRequestUri['request_uri'] = $requestUri;
            return "openid://?" . http_build_query($arDataRequestUri);
        } else {
            $arDataFull['claims'] = json_encode($this->claims);
            $arDataFull['registration'] = json_encode($this->registration);

            return "openid://?" . http_build_query($arDataFull);
        }
    }
}
