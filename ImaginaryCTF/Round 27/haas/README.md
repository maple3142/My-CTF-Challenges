# Hello World as a Service

* Round: 27 (2022/10)
* Category: Misc
* Points: 100
* Solves: 10

## Description

Input your name and generate a Hello World program right now!

## Solution

Java will process unicode escapes like `\u000a` before lexing, so you can escape the inline comment using `\u000a`. Because Java require that the main class should be same as filename, a way to get code execution is to override the `System.out.println`.

Challenge inspired by https://twitter.com/steike/status/1583462929399427074
