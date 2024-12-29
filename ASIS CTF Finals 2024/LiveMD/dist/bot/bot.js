const puppeteer = require('puppeteer')

const SITE = process.env.SITE || 'http://localhost:3000'
const FLAG = process.env.FLAG || 'test{flag}'

const sleep = async ms => new Promise(resolve => setTimeout(resolve, ms))

const launchBrowser = async () => {
	const args = ['--js-flags=--jitless,--no-expose-wasm', '--disable-gpu', '--disable-dev-shm-usage']
	if (new URL(SITE).protocol === 'http:') {
		args.push(`--unsafely-treat-insecure-origin-as-secure=${SITE}`)
	}
	return puppeteer.launch({
		headless: 'new',
		args
	})
}
const browserPromise = launchBrowser()

const visit = async url => {
	const browser = await browserPromise
	const context = await browser.createBrowserContext()
	await context.setCookie({
		name: 'markdown',
		value: encodeURIComponent(`# Flag: **${FLAG}**`),
		domain: new URL(SITE).hostname,
		httpOnly: false
	})
	try {
		const page = await context.newPage()
		await page.goto(url, {
			timeout: 5000,
			waitUntil: 'networkidle0'
		})
	} catch (e) {
		console.log(e)
	} finally {
		await context.close()
	}
}

module.exports = visit

if (require.main === module) {
	visit('https://example.com')
}
