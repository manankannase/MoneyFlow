# =============================================================
# MoneyFlow Dockerfile — Hardened PHP/Apache Image
# =============================================================
FROM php:8.2-apache

LABEL maintainer="MoneyFlow Team"
LABEL description="Secure PHP banking application"

# Install required PHP extensions (PDO only — no mysqli needed)
# --no-install-recommends minimizes attack surface
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    docker-php-ext-install pdo pdo_mysql && \
    apt-get purge -y --auto-remove && \
    rm -rf /var/lib/apt/lists/*

# Enable required Apache modules
RUN a2enmod rewrite headers

# Disable server tokens in Apache config (defense in depth)
RUN echo "ServerTokens Prod" >> /etc/apache2/conf-available/security.conf && \
    echo "ServerSignature Off" >> /etc/apache2/conf-available/security.conf && \
    echo "TraceEnable Off" >> /etc/apache2/conf-available/security.conf

# Security: Harden PHP configuration
RUN { \
    echo 'expose_php = Off'; \
    echo 'display_errors = Off'; \
    echo 'log_errors = On'; \
    echo 'error_log = /var/log/php_errors.log'; \
    echo 'session.cookie_httponly = 1'; \
    echo 'session.cookie_secure = 0'; \
    echo 'session.cookie_samesite = Strict'; \
    echo 'session.use_strict_mode = 1'; \
    echo 'session.use_only_cookies = 1'; \
    echo 'allow_url_fopen = Off'; \
    echo 'allow_url_include = Off'; \
    echo 'max_execution_time = 30'; \
    echo 'max_input_time = 30'; \
    echo 'memory_limit = 128M'; \
    echo 'post_max_size = 10M'; \
    echo 'upload_max_filesize = 5M'; \
    echo 'max_file_uploads = 5'; \
    echo 'disable_functions = exec,passthru,shell_exec,system,proc_open,popen,parse_ini_file,show_source,highlight_file'; \
} > /usr/local/etc/php/conf.d/security.ini

# Set document root
ENV APACHE_DOCUMENT_ROOT=/var/www/html/webroot

RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf && \
    sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# Create uploads directory with proper permissions
# Only the uploads directory is writable by www-data
RUN mkdir -p /var/www/html/webroot/uploads/avatars && \
    chown -R www-data:www-data /var/www/html/webroot/uploads && \
    chmod -R 755 /var/www/html/webroot/uploads

# Set working directory
WORKDIR /var/www/html

# Expose only port 80
EXPOSE 80

# Healthcheck — verify Apache is responding
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost/ || exit 1

CMD ["apache2-foreground"]