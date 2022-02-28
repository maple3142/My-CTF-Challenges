import std/[options, db_sqlite, os, sha1, strutils, strformat, strtabs, json, sugar, httpclient]
import jester
import redis

let appKey = getEnv("APP_KEY", "TESTING_KEY")
let flag = getEnv("FLAG", "TESTING_FLAG")
let adminPass = getEnv("ADMIN_PASS", "admin")
let recaptchaSiteKey = getEnv("RECAPTCHA_SITE_KEY", "")
let recaptchaSecret = getEnv("RECAPTCHA_SECRET", "")

proc sign(m: string, key: string = appKey): string =
  let h = $secureHash(m & key)
  return fmt"{m}:{h}"

proc verify(sig: string, key: string = appKey): Option[string] =
  let toks = sig.rsplit(":", maxsplit=1)
  if len(toks) != 2:
    return none(string)
  let m = toks[0]
  let h = toks[1]
  if $secureHash(m & key) == h:
    return some(m)
  else:
    return none(string)

proc readTemplates(): StringTableRef =
  let tbl = newStringTable()
  for kind, file in walkDir("templates"):
    let name = file.split("/")[1].split(".")[0]
    let content = readFile(file)
    tbl[name] = content
  return tbl

proc initDB(): DbConn =
  let db = open("database.db", "", "", "")
  db.exec(sql"""create table if not exists users (
    username text unique,
    password text
  )""")
  db.exec(sql"""create table if not exists notes (
    author text,
    title text,
    content text
  )""")

  db.exec(sql"""insert into users values ("admin", ?)""", $secureHash(adminPass))
  db.exec(sql"""insert into notes values ("admin", "flag", ?)""", flag)
  return db

proc checkKeys[T](tbl: T, keys: varargs[string]): bool =
  for k in keys:
    if not tbl.hasKey(k):
      return false
  return true

template globalHeaders() =
  result.headers = some(@{
    "Content-Security-Policy": "default-src 'self'; script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; frame-src https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/;",
    "X-Frame-Options": "DENY"
  })

template addHeader(k: string, v: string) =
  # I don't know what's the correct way to do this...
  result.headers = some(result.headers.get() & (@{ k: v }))

template errorHTML(msg: string) =
  resp templates["error"] % msg

template errorJSON(msg: string) = 
  resp %*{
    "status": "error",
    "msg": msg
  }

proc authenticated(request: Request): Option[string] =
  if not request.cookies.hasKey("username"):
    return none(string)
  return verify(request.cookies["username"])

let db = initDB()
let templates = readTemplates()
let redisClient = redis.open("redis")

routes:
  get "/":
    globalHeaders()
    let u = authenticated(request)
    if u.isNone:
      redirect "/login"
      return
    resp templates["index"] % recaptchaSiteKey

  get "/login":
    globalHeaders()
    resp templates["login"]

  post "/login":
    globalHeaders()
    if not checkKeys(request.params, "username", "password"):
      errorHTML "bad parameters"
      return
    let username = request.params["username"]
    let password = request.params["password"]
    let cnt = db.getValue(sql"select count(*) from users where username = ? and password = ?", username, $secureHash(password))
    if cnt == "1":
      setCookie("username", sign(username), httpOnly=true)
      redirect "/"
      return
    # login failed, trying to register
    if len(username) < 8 or len(password) < 8:
      errorHTML "username or password are too short"
      return
    try:
      db.exec(sql"""insert into users values (?, ?)""", username, $secureHash(password))
      setCookie("username", sign(username), httpOnly=true)
      redirect "/"
    except DbError:
      errorHTML "registration failed"
  
  post "/logout":
    globalHeaders()
    setCookie("username", "")
    redirect "/login"

  get "/api/notes":
    globalHeaders()
    let u = authenticated(request)
    if u.isNone:
      resp %*{
        "status": "not logined"
      }
      return
    let target =
      if u.get() == "admin" and request.params.hasKey("user"):
        # admin can see everyone's note
        request.params["user"]
      else:
        u.get()
    let rows = db.getAllRows(sql"select * from notes where author = ?", target)
    let r = collect(newSeq):
      for row in rows: (%*{ "author": row[0], "title": row[1], "content": row[2] })
    resp %r

  post "/api/notes":
    globalHeaders()
    let u = authenticated(request)
    if u.isNone:
      errorJSON "not logined"
      return
    if u.get() == "admin":
      errorJSON "admin shouldn't create any note for security reasons"
      return
    if not request.headers["content-type"].contains("application/json"):
      errorJSON "invalid content type"
      return
    let j = parseJson(request.body)
    if not checkKeys(j, "title", "content"):
      errorJSON "bad parameters"
      return
    db.exec(sql"insert into notes values (?, ?, ?)", u.get(), j["title"].getStr(), j["content"].getStr())
    resp %*{
      "status": "ok"
    }

  post "/api/share":
    globalHeaders()
    let u = authenticated(request)
    if u.isNone:
      errorJSON "not logined"
      return
    if not request.headers["content-type"].contains("application/json"):
      errorJSON "invalid content type"
      return
    let j = parseJson(request.body)
    if not checkKeys(j, "token"):
      errorJSON "bad parameters"
      return
    let check =
      if len(recaptchaSecret) > 0:
        let client = newHttpClient()
        client.headers = newHttpHeaders({ "Content-Type": "application/x-www-form-urlencoded" })
        let body = "secret=$#&response=$#" % [recaptchaSecret, j["token"].getStr()]
        let rj = parseJson(client.postContent("https://www.google.com/recaptcha/api/siteverify", body=body))
        rj["success"].getBool()
      else:
        true
    if check:
      discard redisClient.rpush("queue", u.get())
      resp %*{
        "status": "ok"
      }
    else:
      errorJSON "Recaptcha check failed"
