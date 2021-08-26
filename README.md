# Requirements

- docker
- docker-compose

# Installation

- Open a terminal in the root directory of this repository
- Run ``docker/install.sh`` to create the Nextcloud configuration and the necessary folders.
- Run ``docker-compose -f docker/docker-compose.yml up`` to build and start the Nextcloud instance with the SIOP plugin.
- The instance should now be available at [http://localhost:8080](http://localhost:8080/).
- On first start you have to setup the Nextcloud instance.
Therefore you only need to specify an admin username and password and choose SQLite for the database (default).
- After that you need to go to the ``Apps`` menu and enable the ``OpenID Connect Login`` plugin.