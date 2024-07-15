const puppeteer = require('puppeteer')

const SITE = process.env.SITE || 'http://localhost:3000'
const FLAG = process.env.FLAG || 'test{flag}'
const NOTE_URL = new URL('/~note/', SITE).href

const sleep = async ms => new Promise(resolve => setTimeout(resolve, ms))

let browser = null

const visit = async url => {
	let context = null
	try {
		if (!browser) {
			const args = ['--js-flags=--jitless,--no-expose-wasm', '--disable-gpu', '--disable-dev-shm-usage']
			if (new URL(SITE).protocol === 'http:') {
				args.push(`--unsafely-treat-insecure-origin-as-secure=${SITE}`)
			}
			browser = await puppeteer.launch({
				headless: 'new',
				args
			})
		}

		context = await browser.createBrowserContext()

		const page1 = await context.newPage()
		await Promise.race([
			page1.goto(url, {
				waitUntil: 'networkidle0'
			}),
			sleep(15000)
		])
		await page1.close()

		const page2 = await context.newPage()
		await page2.goto(NOTE_URL, {
			waitUntil: 'networkidle0'
		})
		const iframeHandle = await page2.waitForSelector('iframe')
		const frame = await iframeHandle.contentFrame()
		await frame.type('form textarea', FLAG)
		await frame.click('form button')
		await sleep(1000)
		await page2.close()

		await context.close()
		context = null
	} catch (e) {
		console.log(e)
	} finally {
		if (context) await context.close()
	}
}

module.exports = visit

if (require.main === module) {
	visit('http://example.com')
}
