#!/bin/sh
echo "${FLAG:-not_flag}" > /app/public/flag.txt
nginx &
node src/app.js
