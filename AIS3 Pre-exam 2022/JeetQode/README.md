# JeetQode

* Category: Misc
* Score: 496/500
* Solves: 9/286

## Description

JeetQode - The World's Leading Online JQ Programming Learning Platform

> You don't have to read the source code to solve this challenge. The source code is provided in case that the description isn't clear.

## Overview

這題是使用 [jq](https://stedolan.github.io/jq/) 解三個簡單問題就能拿到 flag 的 PPC 題目。輸入一律以 json 表示，然後需要寫個轉換的 jq program 去把輸入轉換成輸出，類似 Online Judge 的一樣有多筆測資去評斷答案是否正確。輸入有限制 512 字元，但是以這邊出的三個題目來說 512 都是相當充裕的限制，基本上可以忽略不計。

## Solution

### Is Palindrome

輸入是一個字串，輸出是 boolean 代表它是否是迴文而已。

```
Input: "aba"
Output: true

Input: "peko"
Output: false
```

解法就是直接比對 reverse 之後是否相同即可:

```jq
(.|split("")|reverse|join(""))==.
```

### Invert Binary Tree

輸入是個 json 的 binary tree，需要將 left 和 right 交換，左右的子樹也要分別 invert 過才行，

```
Input: {"left": 1, "right": 3}
Output: {"left": 3, "right": 1}

Input: {"left": 1, "right": {"left": 1, "right": 3}}
Output: {"left": {"left": 3, "right": 1}, "right": 1}
```

做法就是寫個 `invert` 函數讓它遞迴下去處理即可，和 tree traversal 一樣:

```jq
def invert: if type=="number" then . else {left:.right|invert,right:.left|invert} end; .|invert
```

> `type` 和 `.|type` 是一樣的意思，單純判斷參數的類型而已

### AST Math

輸入是個精簡過的 Python AST，只包含 `+-*/` 的四則運算而已，輸出就是四則運算出來的結果。

```
Input: {"body": {"left": {"value": 1, "kind": null, "lineno": 1, "col_offset": 0, "end_lineno": 1, "end_col_offset": 1}, "op": "<_ast.Add object at 0x7f0387ccde20>", "right": {"value": 2, "kind": null, "lineno": 1, "col_offset": 2, "end_lineno": 1, "end_col_offset": 3}, "lineno": 1, "col_offset": 0, "end_lineno": 1, "end_col_offset": 3}}
Output: 3

Input: {"body": {"left": {"left": {"value": 8, "kind": null, "lineno": 1, "col_offset": 1, "end_lineno": 1, "end_col_offset": 2}, "op": "<_ast.Mult object at 0x7f20eb76aee0>", "right": {"value": 7, "kind": null, "lineno": 1, "col_offset": 3, "end_lineno": 1, "end_col_offset": 4}, "lineno": 1, "col_offset": 1, "end_lineno": 1, "end_col_offset": 4}, "op": "<_ast.Sub object at 0x7f20eb76ae80>", "right": {"left": {"value": 6, "kind": null, "lineno": 1, "col_offset": 7, "end_lineno": 1, "end_col_offset": 8}, "op": "<_ast.Mult object at 0x7f20eb76aee0>", "right": {"value": 3, "kind": null, "lineno": 1, "col_offset": 9, "end_lineno": 1, "end_col_offset": 10}, "lineno": 1, "col_offset": 7, "end_lineno": 1, "end_col_offset": 10}, "lineno": 1, "col_offset": 0, "end_lineno": 1, "end_col_offset": 11}}
Output: 38
```

解法其實和前題幾乎一樣，只是要透過 `value` 判斷是否是數字，不是的話再判斷 `op` 去檢測 operator 然後做相對應的計算。一樣是用遞迴的方法寫 tree traversal 就很簡單:

```jq
def eval: if .|has("value") then .value elif .op|contains("Add") then (.left|eval)+(.right|eval) elif .op|contains("Sub") then (.left|eval)-(.right|eval) elif .op|contains("Mult") then (.left|eval)*(.right|eval) elif .op|contains("Div") then (.left|eval)/(.right|eval) else null end;.body|eval
```
