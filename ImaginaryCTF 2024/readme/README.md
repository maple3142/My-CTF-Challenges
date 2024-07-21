# readme

* Category: Web
* Score: 100/500
* Solves: 978

## Description

Try to read the `flag.txt` file.

## Solution

```bash
curl --path-as-is 'http://localhost:80/flag.txt/.'
```

## Unintended Solution :sob:

The distribution file contains the flag in `Dockerfile`...
