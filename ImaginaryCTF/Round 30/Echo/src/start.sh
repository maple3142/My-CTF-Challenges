#!/bin/sh
docker run -d --rm -p 8888:8888 -e "FLAG=$FLAG" --name echo echo
