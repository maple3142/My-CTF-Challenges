const puppeteer = require('puppeteer')

const SECRET = process.env.SECRET || 'secret'
const sleep = async ms => new Promise(resolve => setTimeout(resolve, ms))

const auth = `${SECRET}:${SECRET}`
const SITE = process.env.SITE || 'http://rclone:5572'
const tmpurl = new URL(`/?login_token=${encodeURIComponent(btoa(auth))}`, SITE)
tmpurl.username = SECRET
tmpurl.password = SECRET
const LOGIN_URL = tmpurl.href
console.log('[+] LOGIN_URL:', LOGIN_URL)

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
		await page1.goto(LOGIN_URL)
		await page1.close()

		const page2 = await context.newPage()
		await Promise.race([
			page2.goto(url, {
				waitUntil: 'networkidle0'
			}),
			sleep(5000)
		])
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
