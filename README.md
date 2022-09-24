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
- Run ``docker-compose -f docker/docker-compose.yml up`` to build and start the Nextcloud instance with the SIOP plugin.
- If you use ngrok for the first time, initialize it with: ``./ngrok authtoken <TOKEN>``
- Run ``./ngrok http 8080`` and visit the HTTPS url that is displayed in the terminal
- On first start you have to setup the Nextcloud instance.
Therefore you only need to specify an admin username and password and choose SQLite for the database (default).
- After that you need to go to the ``Apps`` menu and enable the ``OpenID Connect Login`` plugin.
