# Requirements

- docker
- docker-compose

# Installation

- Open a terminal in the root directory of this repository
- Run ``docker/install.sh`` to prepare the Nextcloud installation.
- Run ``docker-compose -f docker/docker-compose.yml up`` to build and start the Nextcloud instance with the SIOP plugin.
- If you use ngrok for the first time, initialize it with: ``./ngrok authtoken <TOKEN>``
- Run ``./ngrok http 8080`` and visit the HTTPS url that is displayed in the terminal
- On first start you have to setup the Nextcloud instance.
Therefore you only need to specify an admin username and password and choose SQLite for the database (default).
- After that you need to go to the ``Apps`` menu and enable the ``OpenID Connect Login`` plugin.