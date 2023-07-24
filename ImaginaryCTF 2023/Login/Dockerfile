FROM php:8-apache

RUN /usr/sbin/useradd -u 1000 user

COPY index.php /var/www/html/
COPY init.php /tmp
RUN php /tmp/init.php
RUN chown -R www-data:www-data /var/www/html && \
    chmod -R 444 /var/www/html && \
    chmod 555 /var/www/html && \
    chmod 444 /db.sqlite3

ENV FLAG="ictf{why_are_bcrypt_truncating_my_passwords?!}"
ENV MAGIC="688a35c685a7a654abc80f8e123ad9f0"

VOLUME /var/log/apache2
VOLUME /var/run/apache2

CMD bash -c 'source /etc/apache2/envvars && APACHE_RUN_USER=user APACHE_RUN_GROUP=user /usr/sbin/apache2 -D FOREGROUND'
