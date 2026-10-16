#!/bin/sh
# WARNING: INTENTIONALLY INSECURE DEMO SCRIPT FOR LOCALAUDIT. DO NOT USE.
chmod 777 /var/www/shop/media
scp build.tar.gz deploy@192.168.1.20:/srv/shop/
