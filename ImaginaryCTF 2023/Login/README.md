# Login

* Category: Web
* Score: 100/500
* Solves: 98

## Description

A classic PHP login page, nothing special.

## Solution

- Use union-based SQLi to login as admin to get the magic
- The fact that Bcrypt truncates the password to 72 characters can be used as an oracle to bruteforce the flag.
- See [solve.php](./solve.php).
