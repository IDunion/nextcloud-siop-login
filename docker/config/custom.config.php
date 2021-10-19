<?php
$CONFIG = array (
  'apps_paths' => 
    array (
      0 => 
      array (
        'path' => '/var/www/html/apps',
        'url' => '/apps',
        'writable' => false,
      ),
      1 => 
      array (
        'path' => '/var/www/html/custom_apps',
        'url' => '/custom_apps',
        'writable' => true,
      ),
    ),
  'trusted_domains' => 
    array (
      0 => 'localhost:8080',
      1 => '*.ngrok.io',
  ),
  'memcache.local' => '\OC\Memcache\APCu',
  'overwriteprotocol' => 'https',
  'oidc_login_button_text' => 'Log in with Wallet App',
  'oidc_login_auto_redirect' => false,
  'oidc_login_redir_fallback' => false,
  'oidc_login_hide_password_form' => false,
  'oidc_login_attributes' => 
    array (
        'id' => 'email',
    ),
  'oidc_login_join_attributes' =>
    array(
      'name' => array('first_name', 'last_name'),
  ),
  'oidc_login_schema_config' => array(
    'did:indy:idu:test:3QowxFtwciWceMFr7WbwnM:2:BasicScheme:0.1' => array(
      'first_name', 'last_name', 'email'
    ),
  ),
  'oidc_create_groups' => true,
  'oidc_login_disable_registration' => false,
  'oidc_login_tls_verify' => true,
  'oidc_login_code_challenge_method' => 'S256',
  'debug' => true,
);