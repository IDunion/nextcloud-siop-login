FROM nextcloud:23.0.1

RUN apt-get update 
RUN apt-get install -y \
        gnupg2 \
        software-properties-common \
        libffi-dev

RUN docker-php-ext-install -j$(nproc) sysvmsg ffi

# install indy-sdk
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys CE7709D068DB5E88
RUN add-apt-repository "deb https://repo.sovrin.org/sdk/deb bionic stable"
RUN apt update
RUN apt install -y libindy libindy-dev

COPY php-custom.ini /usr/local/etc/php/conf.d/

RUN sed -i 's/Listen 80/Listen ${PORT}/' /etc/apache2/ports.conf

RUN useradd -m -u 1000 nextcloud
