FROM nextcloud:25.0.4

RUN apt-get update 
RUN apt-get install -y git-core

RUN git clone https://github.com/IDunion/nextcloud-siop-login.git && \
        mkdir -p /var/www/html/config/ && \
        cp nextcloud-siop-login/docker/sd-jwt.config.php /var/www/html/config/ && \
        mkdir -p /var/www/html/apps/ && \
        mv nextcloud-siop-login/ /var/www/html/apps/ssi_login/

RUN useradd -m -u 1000 nextcloud
