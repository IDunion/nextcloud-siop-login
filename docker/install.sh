#!/bin/bash

mkdir -p docker/apps docker/config docker/data docker/themes

echo "<?php
\$CONFIG = array (
  'htaccess.RewriteBase' => '/',
  'memcache.local' => '\\OC\\Memcache\\APCu',
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
  'instanceid' => 'ocjaniirtb36',
  'passwordsalt' => 'br7UHqtUdDQmQ1jqKI0qAF5HLAiDMh',
  'secret' => 'UXdBZ25B/eXdM4ECPwVZFdwWL9kQxlwsN4qYOeoRDC/Ye3k8',
  'trusted_domains' => 
  array (
    0 => 'localhost:8080',
  ),
  'datadirectory' => '/var/www/html/data',
  'dbtype' => 'sqlite3',
  'version' => '22.1.0.1',
  'overwrite.cli.url' => 'http://localhost:8080',
  'installed' => false,
  'oidc_login_button_text' => 'Log in with Wallet App',
  'oidc_login_auto_redirect' => false,
  'oidc_login_redir_fallback' => false,
  'oidc_login_hide_password_form' => false,
  'oidc_login_attributes' => 
  array (
    'mail' => 'email',
  ),
  'oidc_create_groups' => true,
  'oidc_login_disable_registration' => false,
  'oidc_login_tls_verify' => true,
  'oidc_login_code_challenge_method' => 'S256',
  'maintenance' => false,
);
" > docker/config/config.php

touch docker/config/CAN_INSTALL
