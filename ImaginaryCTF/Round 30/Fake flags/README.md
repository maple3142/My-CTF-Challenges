# Fake Flags

* Round: 30 (2023/01)
* Category: Web
* Points: 50
* Solves: 87

## Description

The real flag is hidden in these fake flags! (Warning: The website may trigger seizure)

https://ictf-fake-flags.netlify.app/

## Solution

First, you need to open devtool and stop the anti-debugging `debugger` statement then disable that annoying animation. Some elements are hidden by `ads-banner`, so you need to disable adblockers to actually see them. The flag is also split into multiple span elements and ZWNJ, so you need to remove them to find the flag.

```javascript
document.body.textContent.replaceAll('\u200c','').match(/iiccttff{.*?}/)[0]
```
