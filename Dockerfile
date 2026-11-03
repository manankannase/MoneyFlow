FROM php:8.4-apache-trixie@sha256:4af38a0245996e700e20ec211b9f1c44fb789ad8cc7d24c7ea81ff382b641052
RUN apt-get update && apt-get install -y --no-install-recommends libpng-dev libjpeg62-turbo-dev \
    && docker-php-ext-configure gd --with-jpeg \
    && docker-php-ext-install pdo_mysql gd \
    && apt-mark manual libpng16-16t64 libjpeg62-turbo \
    && apt-get purge -y --auto-remove $PHPIZE_DEPS libc6-dev linux-libc-dev curl libpng-dev libjpeg62-turbo-dev \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod headers remoteip \
    && sed -i 's/Listen 80/Listen 8080/' /etc/apache2/ports.conf \
    && mkdir -p /var/lib/moneyflow/avatars /var/run/apache2 /var/lock/apache2 \
    && chown -R www-data:www-data /var/lib/moneyflow /var/run/apache2 /var/lock/apache2
COPY apache.conf /etc/apache2/sites-available/000-default.conf
COPY deploy/php.ini /usr/local/etc/php/conf.d/moneyflow.ini
WORKDIR /var/www/html
COPY --chown=root:root settings settings
COPY --chown=root:root utilities utilities
COPY --chown=root:root layouts layouts
COPY --chown=root:root webroot webroot
COPY --chown=root:root tests tests
USER www-data
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 CMD php -r '$s=@fsockopen("127.0.0.1",8080); if(!$s)exit(1); fwrite($s,"GET /health.php HTTP/1.0\r\nHost: localhost\r\n\r\n"); exit(str_ends_with(stream_get_contents($s),"ok")?0:1);'
CMD ["apache2-foreground"]
