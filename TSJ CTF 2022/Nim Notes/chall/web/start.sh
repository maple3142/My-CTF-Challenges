#!/bin/sh
rm database.db 2>/dev/null
nginx &
/app/app
