# Stage 1:
# - Get Shaarli sources
# - Build documentation
FROM dalibo/pandocker:stable as docs
ADD . /pandoc/shaarli
RUN cd /pandoc/shaarli \
    && make htmldoc \
    && rm -rf .git

# Stage 2:
# - Resolve PHP dependencies with Composer
FROM composer:latest as composer
COPY --from=docs /pandoc/shaarli /app/shaarli
RUN cd shaarli \
    && composer --prefer-dist --no-dev install

# Stage 3:
# - Shaarli image
FROM debian:jessie
LABEL maintainer="Shaarli Community"

ENV TERM dumb
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
       ca-certificates \
       curl \
       nginx-light \
       php5-curl \
       php5-fpm \
       php5-gd \
       php5-intl \
       supervisor \
    && apt-get clean

RUN sed -i 's/post_max_size.*/post_max_size = 10M/' /etc/php5/fpm/php.ini \
    && sed -i 's/upload_max_filesize.*/upload_max_filesize = 10M/' /etc/php5/fpm/php.ini

COPY .docker/nginx.conf /etc/nginx/nginx.conf
COPY .docker/supervised.conf /etc/supervisor/conf.d/supervised.conf

WORKDIR /var/www
COPY --from=composer /app/shaarli shaarli
RUN rm -rf html \
    && chown -R www-data:www-data .

VOLUME /var/www/shaarli/data

EXPOSE 80

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
