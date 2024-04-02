# FLT-1337

* Round: 43 (2024/03)
* Category: Misc
* Points: 50
* Solves: 9

## Description

Let's disprove Fermat Last Theorem!

## Solution

Sage use eval when you pass a string to multivariate polynomial ring, so `__import__('os').system('sh')` pops a shell.

Relevant issue: [sagemath/sage #37641](https://github.com/sagemath/sage/issues/37641)
