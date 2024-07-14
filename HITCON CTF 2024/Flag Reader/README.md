# Flag Reader

* Category: Misc
* Score: 271/500
* Solves: 24

## Description

Update a tar with flag.txt (if you can), and I will read it for you.

## Overview

Players are asked to upload a tar, and the server side would about if the tar contains any non-regular files or files with names containing `flag.txt`. Otherwise it would extract the tar with `tar` (busybox) command and read the content of `flag.txt`.

The flag is located at `/flag.txt`.

## Solution

Apparently, the target is to upload a tar with a `flag.txt` symlink to `/flag.txt` that also bypass the server side check. Since it checks the tar using Python's builtin `tarfile` module and does the extraction with `tar` command, we need to find a parser differential between them.

My intended solution is to exploit the [`_apply_pax_info`](https://github.com/python/cpython/blob/a2bec77d25b11f50362a7117223f6d1d5029a909/Lib/tarfile.py#L1553-L1574) function, which will set some properties from pax headers.

The most relevant code to my solution is:

```python
PAX_NUMBER_FIELDS = {
    "atime": float,
    "ctime": float,
    "mtime": float,
    "uid": int,
    "gid": int,
    "size": int
}
# omitted...
class TarFile(object):
    # omitted...
    def _apply_pax_info(self, pax_headers, encoding, errors):
        """Replace fields with supplemental information from a previous
           pax extended or global header.
        """
        for keyword, value in pax_headers.items():
            if keyword == "GNU.sparse.name":
                setattr(self, "path", value)
            elif keyword == "GNU.sparse.size":
                setattr(self, "size", int(value))
            elif keyword == "GNU.sparse.realsize":
                setattr(self, "size", int(value))
            elif keyword in PAX_FIELDS:
                if keyword in PAX_NUMBER_FIELDS:
                    try:
                        value = PAX_NUMBER_FIELDS[keyword](value)
                    except ValueError:
                        value = 0
                if keyword == "path":
                    value = value.rstrip("/")
                setattr(self, keyword, value)

        self.pax_headers = pax_headers.copy()
```

So if `pax_headers` contains a `size` that would result in `ValueError` in Python side but not in `tar` command, then Python would treat that file have a size of 0 while `tar` command won't. This difference will make Python's tar to ignore the file after it since it would treat the content of the first file as the header of the second file.

To actually achieve this, we can set `size` to a string that is a number with a trailing `\x00`, so Python's `int` would raise `ValueError` and `tar` will just ignore it because it is processed as a null-terminated string.

See [exp.py](./solution/exp.py) for the full solver.
