const http = require('http')
const crypto = require('crypto')
const querystring = require('querystring')

function readAll(req) {
	return new Promise((resolve, reject) => {
		const chunks = []
		req.on('data', chunk => chunks.push(chunk))
		req.on('end', () => resolve(Buffer.concat(chunks)))
		req.on('error', reject)
	})
}

const notes = new Map()
const DELETE_TIMEOUT = 5 * 60 * 1000 // 5 minutes

http.createServer(async (req, res) => {
	console.log(req.method, req.url)
	const url = new URL(req.url, 'http://localhost')
	if (url.pathname === '/') {
		res.writeHead(200, { 'content-type': 'text/html' })
		res.end(`
			<h1>Note</h1>
			<form action="/create" method="post">
				<p>
					<textarea name="content" placeholder="Insert any content here" required rows="10" cols="40"></textarea>
				</p>
				<button>Create</button>
			</form>
		`)
		return
	} else if (url.pathname === '/create' && req.method === 'POST') {
		const ctlen = parseInt(req.headers['content-length'], 10)
		if (isNaN(ctlen) || ctlen > 1024) {
			res.writeHead(413, { 'content-type': 'text/plain' })
			res.end('Request Entity Too Large')
			return
		}
		const body = await readAll(req)
		const form = querystring.parse(body.toString())
		const id = crypto.randomUUID()
		notes.set(id, form.content)
		res.writeHead(302, { location: `/${id}` })
		res.end()

		// schedule deletion
		setTimeout(() => {
			notes.delete(id)
		}, DELETE_TIMEOUT)
		return
	} else {
		const id = url.pathname.slice(1)
		if (notes.has(id)) {
			res.writeHead(200, { 'content-type': 'text/plain', 'x-content-type-options': 'nosniff' })
			res.end(notes.get(id))
		} else {
			res.writeHead(404, { 'content-type': 'text/plain' })
			res.end('Not Found')
		}
	}
}).listen(3001)
