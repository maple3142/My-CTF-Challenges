const http = require('http')
const https = require('https')
const fs = require('fs')

const VIEWER_HTML = fs.readFileSync('viewer.html', 'utf8')
const PURIFY_JS = fs.readFileSync('purify.js', 'utf8')
const VIEWER_JS = fs.readFileSync('viewer.js', 'utf8')

function createProxy({ site, requestHook, responseHook }) {
	return (req, res) => {
		const target = new URL(req.url, site)
		console.log('proxy', req.method, target.href)
		const hostname = target.hostname
		const port = target.port || (target.protocol === 'https:' ? 443 : 80)
		const path = target.pathname + target.search
		const request = target.protocol === 'https:' ? https.request : http.request
		delete req.headers.host // might cause the server to return wrong certificate for https hosts
		const reqObj = {
			hostname,
			port,
			path,
			method: req.method,
			headers: req.headers
		}
		const ctx = { target, req, res }
		if (requestHook) {
			requestHook(ctx, reqObj)
		}
		const proxyReq = request(reqObj, proxyRes => {
			if (responseHook) {
				responseHook(ctx, reqObj, proxyRes)
			}
			res.writeHead(proxyRes.statusCode, proxyRes.statusMessage, proxyRes.headers)
			proxyRes.pipe(res)
			proxyRes.on('error', err => {
				console.error('proxyRes error', err)
			})
		})
		req.pipe(proxyReq)
		proxyReq.on('error', err => {
			console.error('proxyReq error', err)
			try {
				res.writeHead(500, DEFAULT_HEADERS)
				res.end(`proxy error: ${err.message}`)
			} catch {}
		})
	}
}
const SECURE_HEADERS = {
	'content-security-policy':
		"default-src 'self'; style-src 'unsafe-inline' *; img-src *; font-src *; frame-src 'self' data:",
	'x-content-type-options': 'nosniff'
}
const DEFAULT_HEADERS = {
	'content-type': 'text/plain',
	...SECURE_HEADERS
}
const proxies = new Map()
function addToProxy(name, site) {
	const handler = createProxy({
		site,
		requestHook: (ctx, req) => {
			delete req.headers.cookie // cookies are a security risk
			delete req.headers.referer // bypass hotlink protection
		},
		responseHook: (ctx, req, res) => {
			res.headers['x-target-url'] = ctx.target.href
			// set secure headers
			Object.assign(res.headers, SECURE_HEADERS)
			// default to text/plain
			if (!res.headers['content-type']) res.headers['content-type'] = 'text/plain'
			// cache can be used to track users :(
			delete res.headers['cache-control']
			delete res.headers['expires']
			delete res.headers['etag']
			delete res.headers['last-modified']
			// block scripts just in case
			if (
				res.headers['content-type'].toLowerCase().includes('script') ||
				req.headers['sec-fetch-dest'] === 'script'
			) {
				res.headers['content-length'] = '0'
				delete res.headers['transfer-encoding']
			}
			const siteBase = `http://localhost/~${name}/`
			const resolveUrl = href =>
				href.startsWith('/')
					? new URL(href.replace(/^\/+/, './/'), siteBase)
					: new URL(href, `http://localhost${ctx.req.url}`)
			if (res.headers.location) {
				if (/^https?:\/\//i.test(res.headers.location)) {
					// workaround for fetch() inability to read redirect location from headers
					res.statusCode = 200
					res.headers['x-location'] = res.headers.location
					res.headers['content-type'] = 'text/plain'
					delete res.headers.location
					return
				}
				const newUrl = resolveUrl(res.headers.location)
				res.headers.location = newUrl.pathname + newUrl.search + newUrl.hash
			}
		}
	})
	proxies.set(name, { site, handler })
}
const DEFAULT_SITES = {
	note: 'http://localhost:3001/',
	example: 'https://example.com/',
	maple3142: 'https://blog.maple3142.net/',
	splitline: 'https://blog.splitline.tw/',
	lebr0nli: 'https://lebr0nli.github.io/blog/',
	orange: 'https://blog.orange.tw/',
	strellic: 'https://brycec.me/',
	arxenix: 'https://blog.ankursundara.com/',
	huli: 'https://blog.huli.tw/',
	st98: 'https://nanimokangaeteinai.hateblo.jp/',
	ark: 'https://blog.arkark.dev/',
	zeyu2001: 'https://ctf.zeyu2001.com/',
	nodedoc: 'https://nodejs.org/docs/latest/api/',
	pythondoc: 'https://docs.python.org/3/',
	godoc: 'https://go.dev/doc/',
	mdn: 'https://developer.mozilla.org/en-US/',
	hn: 'https://news.ycombinator.com/',
	ctftime: 'https://ctftime.org/',
	http: 'https://httpbingo.org/'
}

for (const [name, site] of Object.entries(DEFAULT_SITES)) {
	addToProxy(name, site)
}

const DEFAULT_SITES_HTML =
	'<section><h2>Public Sites</h2><ul>\n' +
	Object.keys(DEFAULT_SITES)
		.map(name => `<li><a href="/~${name}/" target="_blank">${name}</a></li>`)
		.join('\n') +
	'\n</ul></section>'

const INDEX_HTML =
	`<!DOCTYPE html><html>
	<head>
	<meta charset="utf-8" />
	<title>Private Browsing +</title>
	</head>
	<body>
	<h1>Private Browsing +</h1>
	<section>
		<p>This is a proxy to your favorite websites that automatically strips unnecessary annoyances.</p>
		<h2>Features</h2>
		<ul>
			<li>Most traffic is proxied through this server.</li>
			<li>All scripts are blocked for privacy and performance reasons.</li>
			<li>JavaScript is needed for this to function as it will try to make best effort to "un-break" a website.</li>
			<li><strong>Does not</strong> work on Firefox due to some weird bugs.</li>
		</ul>
	</section>
	<section>
		<h2>Create</h2>
		<form action="/create">
			<input name="name" placeholder="Name" required>
			<input name="site" placeholder="Site URL" required>
			<button>Create</button>
		</form>
	</section>
	` +
	DEFAULT_SITES_HTML +
	'</body></html>'

const app = (req, res) => {
	const url = new URL(req.url, `http://localhost`)
	if (url.pathname === '/robots.txt') {
		// just in case any crawler comes
		res.writeHead(200, DEFAULT_HEADERS)
		res.end('User-agent: *\nDisallow: /\n')
		return
	} else if (url.pathname === '/purify.js') {
		res.writeHead(200, { ...DEFAULT_HEADERS, 'content-type': 'text/javascript' })
		res.end(PURIFY_JS)
		return
	} else if (url.pathname === '/viewer.js') {
		res.writeHead(200, { ...DEFAULT_HEADERS, 'content-type': 'text/javascript' })
		res.end(VIEWER_JS)
		return
	} else if (url.pathname.startsWith('/~')) {
		const chunks = url.pathname.split('/')
		if (chunks.length < 3) {
			// redirect /~xxx to /~xxx/
			res.writeHead(302, {
				...DEFAULT_HEADERS,
				Location: url.pathname + '/'
			})
			res.end()
			return
		}
		const name = chunks[1].slice(1)
		const proxy = proxies.get(name)
		if (!proxy) {
			res.writeHead(404, DEFAULT_HEADERS)
			res.end('404 Not Found')
			return
		}
		if (
			req.headers['sec-fetch-mode'] &&
			req.headers['sec-fetch-mode'] !== 'navigate' &&
			req.headers['sec-fetch-site'] === 'same-origin'
		) {
			req.url = chunks.slice(2).join('/')
			proxy.handler(req, res)
		} else {
			res.writeHead(200, { ...DEFAULT_HEADERS, 'content-type': 'text/html' })
			res.end(VIEWER_HTML.replace('SITEB64', btoa(proxy.site)))
		}
	} else if (url.pathname.startsWith('/create')) {
		let site = url.searchParams.get('site')
		const name = url.searchParams.get('name')
		if (!site || !name) {
			res.writeHead(400, DEFAULT_HEADERS)
			res.end('Missing site or name')
			return
		}
		try {
			site = new URL(site)
			if (site.protocol !== 'http:' && site.protocol !== 'https:') throw new Error()
		} catch {
			res.writeHead(400, DEFAULT_HEADERS)
			res.end('Invalid site URL')
			return
		}
		if (name.length < 8 || name.includes('/') || name.includes('\\') || name.includes('.')) {
			res.writeHead(400, DEFAULT_HEADERS)
			res.end('Invalid name')
			return
		}
		if (proxies.has(name)) {
			res.writeHead(400, DEFAULT_HEADERS)
			res.end('Name already taken')
			return
		}
		addToProxy(name, site)
		res.writeHead(201, DEFAULT_HEADERS)
		res.end(`site created at /~${name}`)
	} else if (url.pathname === '/') {
		res.writeHead(200, { ...DEFAULT_HEADERS, 'content-type': 'text/html' })
		res.end(INDEX_HTML)
	} else {
		res.writeHead(404, DEFAULT_HEADERS)
		res.end('404 Not Found')
	}
}
const PORT = process.env.PORT || 3000
http.createServer(app).listen(PORT)
if (process.env.TLS_CERT) {
	const opts = {
		key: fs.readFileSync(process.env.TLS_KEY),
		cert: fs.readFileSync(process.env.TLS_CERT)
	}
	const PORT = process.env.TLS_PORT || 3443
	https.createServer(opts, app).listen(PORT)
}
