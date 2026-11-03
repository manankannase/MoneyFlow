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