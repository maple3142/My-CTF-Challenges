# Lisp.js

* Category: Misc
* Score: 342/500
* Solves: 9

## Description

A brand new Lisp interpreter implemented in JavaScript!

## Overview

There is a Lisp interpreter implemented in JavaScript, and you can execute arbitrary Lisp code with it. The objective is to execute `/readflag`.

Dynamic code generation and `__proto__` are disabled.

## Solution

Since you can do arbitrary attribute access, it is possible to climb the function call stack from any function using `.caller`, and you will eventually reach the CJS wrapper function: `function(exports, require, module, __filename, __dirname) { ... }`

From there, you can find the exported function of `runtime.js` from `require.cache`, and `extendedScope` have `j2l` and `l2j` functions that can help you call arbitrary JS functions from Lisp. So now you can call `require('child_process').execSync` to execute `./readflag`.

[exp.lisp](./exp.lisp) is my solution. Simply `cat exp.lisp | nc chal-lispjs.chal.hitconctf.com 1337` to get the flag.
