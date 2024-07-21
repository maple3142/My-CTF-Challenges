const flag = process.env.FLAG || 'ictf{this_is_a_fake_flag}'

Bun.serve({
	async fetch(req) {
		const url = new URL(req.url)
		if (url.pathname === '/') return new Response('Hello, World!')
		if (url.pathname.startsWith('/flag.txt')) return new Response(flag)
		return new Response(`404 Not Found: ${url.pathname}`, { status: 404 })
	},
	port: 3000
})
Bun.serve({
	async fetch(req) {
		if (req.url.includes('flag')) return new Response('Nope', { status: 403 })
		const headerContainsFlag = [...req.headers.entries()].some(([k, v]) => k.includes('flag') || v.includes('flag'))
		if (headerContainsFlag) return new Response('Nope', { status: 403 })
		const url = new URL(req.url)
		if (url.href.includes('flag')) return new Response('Nope', { status: 403 })
		return fetch(new URL(url.pathname + url.search, 'http://localhost:3000/'), {
			method: req.method,
			headers: req.headers,
			body: req.body
		})
	},
	port: 4000 // only this port are exposed to the public
})
