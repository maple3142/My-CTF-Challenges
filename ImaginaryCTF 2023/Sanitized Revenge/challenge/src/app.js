const express = require('express')
const rateLimit = require('express-rate-limit')
const puppeteer = require('puppeteer')

const port = process.env.PORT || 3000
const flag = process.env.FLAG || 'jctf{fake_flag}'

let browser

const app = express()
app.use((req, res, next) => {
	res.setHeader('Content-Security-Policy', "default-src 'self'")
	next()
})
app.use(express.json())
app.use(
	express.static('static', {
		index: 'index.xhtml'
	})
)

app.get('/source', (req, res) => {
	res.type('text').sendFile(__filename)
})

async function visit(html) {
	const path = '/?html=' + encodeURIComponent(html)
	console.log(`[+] visiting ${path}`)
	const url = `http://localhost:${port}${path}`
	const context = await browser.createIncognitoBrowserContext()
	const page = await context.newPage()
	await page.setCookie({
		name: 'flag',
		value: flag,
		domain: 'localhost',
		sameSite: 'strict',
		httpOnly: false
	})
	try {
		await page.goto(url, { waitUntil: 'networkidle0' })
	} catch (e) {
		console.error(`[+] error visting ${path}`, e)
	}
	await page.close()
	await context.close()
}

app.post(
	'/report',
	rateLimit({
		windowMs: 60 * 1000,
		max: 5,
		message: { error: 'Too many requests, try again later' }
	}),
	(req, res) => {
		const { html } = req.body

		if (!html || typeof html !== 'string') {
			return res.json({
				error: 'html must be a string'
			})
		}
		visit(html)
		res.json({
			success: true,
			message: 'Reported'
		})
	}
)

app.use((req, res) => {
	res.type('text').send(`Page ${req.path} not found`)
})

app.listen(port, async () => {
	console.log(`Listening on http://0.0.0.0:${port}`)
	browser = await puppeteer.launch({
		pipe: true,
		dumpio: true,
		args: ['--js-flags=--jitless,--no-expose-wasm', '--disable-gpu', '--disable-dev-shm-usage', '--no-sandbox'],
		headless: 'new'
	})
	console.log('Browser launched')
})
