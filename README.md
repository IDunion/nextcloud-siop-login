# Description

This Nexcloud plugin provides the capability to login into Nextcloud with a wallet that supports [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html). 
So far only the [Lissi Wallet](https://lissi.id/) is compatible with this plugin.
The exact protocol used in this plugin is documented [here](https://github.com/IDunion/nextcloud-siop-docu).
This code is only for demonstration purposes right now and is not used in production. 
If you find any bugs please open an Issue or create a Pull Request. 
The code is based on the [Nextcloud OIDC Login](https://github.com/pulsejet/nextcloud-oidc-login) 
plugin.

# Test the Plugin Locally

## Requirements

- docker
- docker-compose

## Installation

- Open a terminal in the root directory of this repository
- Run ``docker/install.sh`` to prepare the Nextcloud installation.

---

**Option 1: SD-JWT:**

- Run ``docker-compose -f docker/docker-compose-sd-jwt.yml up`` to start the Nextcloud instance with the SSI plugin.

---

**Option 2: Anoncreds and JSON-LD with BBS+:**

- Build the JSON-LD BBS+ verification service docker container (``nextcloud-credential`` branch) ([separate project](https://github.com/IDunion/jsonld-bbs-verification-service/tree/nextcloud-credential))
- Run ``docker-compose -f docker/docker-compose.yml up`` to build and start the Nextcloud instance with the SSI plugin.

---

- If you use ngrok for the first time, initialize it with: ``ngrok authtoken <TOKEN>``
- Run ``ngrok http 80`` and visit the HTTPS url that is displayed in the terminal
- On first start you have to setup the Nextcloud instance.
Therefore you only need to specify an admin username and password and choose SQLite for the database (default).
- After that you need to go to the ``Apps`` menu and enable the ``SSI Login`` plugin.

# Development

## Build JS Bundle

``NODE_OPTIONS=--openssl-legacy-provider webpack build --config webpack.config.js``

# Known Issues

## On-Device Flow: Being redirected to the login screen after authentication

If the pooling endpoint is pooled after the /oidc/callback endpoint is called and before
the browser is redirected to the dashboard, the user will be redirected directly back
to the login page. This happens because, for some reason, the pooling request in this case
is setting a new cookie that is not signed in. The pooling endpoint does not set any cookies,
so there is probably some middleware involved that is post-processing the request.
This is only a problem if the pooling timeout is set to a very low value. 
If the timeout is set to 2 seconds, this problem usually does not occur.
