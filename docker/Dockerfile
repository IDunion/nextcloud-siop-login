FROM nextcloud:22.1.0

RUN apt-get update 
RUN apt-get install -y \
        libfreetype6-dev \
        libjpeg62-turbo-dev \
        libpng-dev \
        libzip-dev \
        gnupg2 \
        software-properties-common \
        libffi-dev \
        gdb
RUN docker-php-ext-configure gd --with-freetype --with-jpeg
RUN docker-php-ext-install -j$(nproc) gd sysvmsg zip ffi

RUN pecl install xdebug \
    && docker-php-ext-enable xdebug

# install indy-sdk
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys CE7709D068DB5E88
RUN add-apt-repository "deb https://repo.sovrin.org/sdk/deb bionic stable"
RUN apt update
RUN apt install -y libindy libindy-dev

COPY xdebug.ini /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini
COPY error_reporting.ini /usr/local/etc/php/conf.d/error_reporting.ini

RUN sed -i 's/Listen 80/Listen ${PORT}/' /etc/apache2/ports.conf