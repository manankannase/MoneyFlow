FROM php:8.2-apache

# Install system dependencies for GD image processing, healthcheck, and TLS cert generation
RUN apt-get update && apt-get install -y \
    libpng-dev libjpeg62-turbo-dev libfreetype6-dev libwebp-dev curl openssl \
    && rm -rf /var/lib/apt/lists/*

# Install required PHP extensions (including GD for secure image re-encoding)
RUN docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp \
    && docker-php-ext-install pdo pdo_mysql mysqli gd

# FIX: Enable Apache mod_rewrite, mod_headers, mod_ssl for HTTPS redirect
RUN a2enmod rewrite headers ssl

# FIX #9: Suppress Apache version disclosure.
# Debian's default security.conf ships with ServerTokens OS + ServerSignature On.
# We patch it in-place — nothing else can override these after this point.
# ServerTokens Prod  → Server: Apache  (no version, no OS)
# ServerSignature Off → no version footer on Apache error pages
# TraceEnable is already Off in the default security.conf.
RUN sed -i 's/^ServerTokens .*/ServerTokens Prod/' /etc/apache2/conf-available/security.conf \
    && sed -i 's/^ServerSignature .*/ServerSignature Off/' /etc/apache2/conf-available/security.conf

# SECURITY: Generate self-signed TLS certificate at build time for HTTPS
# This ensures all traffic is encrypted without needing pre-built cert files in the repo
RUN mkdir -p /etc/apache2/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/apache2/ssl/selfsigned.key \
    -out /etc/apache2/ssl/selfsigned.crt \
    -subj "/C=US/ST=State/L=City/O=MoneyFlow/OU=Dev/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" && \
    chmod 600 /etc/apache2/ssl/selfsigned.key && \
    chmod 644 /etc/apache2/ssl/selfsigned.crt

# Set document root
ENV APACHE_DOCUMENT_ROOT /var/www/html/webroot

RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# Create uploads directory with proper permissions
# TIP: Changed ownership to www-data so Apache can actually write to it
RUN mkdir -p /var/www/html/webroot/uploads/avatars && \
    chown -R www-data:www-data /var/www/html/webroot/uploads && \
    chmod -R 755 /var/www/html/webroot/uploads

# Set working directory
WORKDIR /var/www/html

# FIX V5: Remove debug/test files that should never be in production.
# Even if test_hash.php is accidentally re-added to the repo, this line
# ensures it is stripped from every Docker image build.
RUN rm -f /var/www/html/webroot/test_hash.php

# FIX V2 (defence-in-depth): Ensure .htaccess blocking PHP execution
# is always present in the avatars upload directory.
RUN printf 'php_flag engine off\nOptions -ExecCGI\nAddType text/plain .php .php3 .php4 .php5 .phtml .phar\n'     > /var/www/html/webroot/uploads/avatars/.htaccess

# Disable dangerous PHP shell-execution functions.
# If a zero-day in GD, PDO, or any extension ever allowed arbitrary code
# injection, these functions would give an attacker a full OS shell.
# Removing them means PHP can still run normally but cannot spawn processes.
RUN printf "disable_functions = system,exec,shell_exec,passthru,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,phpinfo\nexpose_php = Off\n" \
    > /usr/local/etc/php/conf.d/security-hardening.ini

EXPOSE 80 443

# FIX #10: Apache requires root to bind ports 80/443 (privileged ports < 1024).
# The master process starts as root then drops worker privileges to www-data
# automatically via the User/Group directives in apache2.conf.
# Mitigation: file ownership and permissions are tightly scoped (www-data for
# uploads only), and directory traversal outside webroot/ is denied in apache.conf.

# FIX #11: Container health check — verifies HTTPS is serving responses.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsk https://localhost/ -o /dev/null || exit 1

CMD ["apache2-foreground"]