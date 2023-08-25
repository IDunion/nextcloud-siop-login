FROM nextcloud:25.0.4

RUN apt-get update 
RUN apt-get install -y git-core

RUN git clone https://github.com/IDunion/nextcloud-siop-login.git && \
        mkdir -p /var/www/html/config/ && \
        cp nextcloud-siop-login/docker/sd-jwt.config.php /var/www/html/config/ && \
        mkdir -p /var/www/html/custom_apps/ && \
        mv nextcloud-siop-login/ /var/www/html/custom_apps/ssi_login/ && \
        chown -R 1000:1000 /var/www/html/custom_apps/

RUN useradd -m -u 1000 nextcloud
