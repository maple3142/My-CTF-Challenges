const express = require('express')
const turnstile = require('./turnstile')
const visit = require('./bot')

const TITLE = process.env.TITLE || 'Admin Bot'
const PORT = process.env.PORT || 8000
const URL_CHECK_REGEX_RAW = process.env.URL_CHECK_REGEX || '^https?://.{1,256}$'
const URL_CHECK_REGEX = new RegExp(URL_CHECK_REGEX_RAW)
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || '1x00000000000000000000AA'
const SITE = process.env.SITE || 'http://localhost:3000'

const INDEX_HTML = `
<!DOCTYPE html>
<head>
<title>${TITLE}</title>
<link rel="stylesheet" href="https://cdn.simplecss.org/simple.css">
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body>
<main>
<h1>${TITLE}</h1>
<p>Target URL: <code>${SITE}</code></p>
<form action="/submit" method="POST" class="form">
    <input type="text" name="captcha" style="display: none">
    <p>
        <label>URL</label>
        <input type="text" name="url" pattern="${URL_CHECK_REGEX_RAW}" required>
    </p>
    <p>
		<div class="cf-turnstile" data-sitekey="${TURNSTILE_SITE_KEY}"></div>
    </p>
    <p>
        <button type="submit">Submit</button>
    </p>
</form>
</main>
</body>
`

const app = express()
app.use(express.urlencoded({ extended: false }))

app.get('/', (req, res) => {
	res.send(INDEX_HTML)
})
app.post('/submit', turnstile, async (req, res) => {
	const { url } = req.body
	if (!url || !URL_CHECK_REGEX.test(url)) {
		return res.status(400).send('Invalid URL')
	}

	try {
		console.log(`[+] Sending ${url} to bot`)
		await visit(url)
		res.send('OK')
	} catch (e) {
		console.log(e)
		res.status(500).send('Something is wrong...')
	}
})

app.listen(PORT, () => {
	console.log(`Listening on http://localhost:${PORT}`)
})
if (process.env.TLS_CERT) {
	const https = require('https')
	const fs = require('fs')
	const opts = {
		key: fs.readFileSync(process.env.TLS_KEY),
		cert: fs.readFileSync(process.env.TLS_CERT)
	}
	const PORT = process.env.TLS_PORT || 8443
	https.createServer(opts, app).listen(PORT)
}
