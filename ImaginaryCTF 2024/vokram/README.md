# vokram

* Category: Reversing
* Score: 471/500
* Solves: 19

## Description

Can you find what this (very inefficient) VM is doing?

## Solution

The VM implements [Markov algorithm](https://en.wikipedia.org/wiki/Markov_algorithm), and the flag checker does these steps:

1. Convert the flag into a ternary string
2. Apply (mod 3) lfsr state transition `N` times
3. Check if the result matches a certain ternary string

So you can find the `N` and the lfsr taps by analyzing the substitution rules, then it is easy to reverse the state transition and get the flag.

It is possible to inspect the intermediate states and solve a linear equation to find its transition matrix instead.
