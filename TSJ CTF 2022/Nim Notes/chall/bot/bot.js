const puppeteer = require('puppeteer')
const redis = require('redis')
const { default: PQueue } = require('p-queue')

const MAX_INSTANCES = 4

function sleep(ms) {
	return new Promise(resolve => setTimeout(resolve, ms))
}

async function visit(browser, user, id) {
	console.log(`[${id}] Visiting ${user} page`)
	const context = await browser.createIncognitoBrowserContext()
	const page = await context.newPage()
	await page.goto(`${process.env.CHALL_HOST}/login`, { waitUntil: 'load' })
	await page.$eval('#username', el => (el.value = 'admin'))
	await page.$eval('#password', (el, v) => (el.value = v), process.env.ADMIN_PASS)
	await page.click('button[type=submit]')

	try {
		const url = `${process.env.CHALL_HOST}/?user=${user}`
		console.log(`[${id}] Browsing ${url}`)
		await page.goto(url, {
			waitUntil: 'networkidle2'
		})
	} catch (err) {
		console.log(err)
	}

	await sleep(10 * 1000)

	await page.close()
	await context.close()

	console.log(`[${id}] Done visiting ${user} page`)
}

;(async () => {
	const r = redis.createClient({
		url: 'redis://redis:6379'
	})
	await r.connect()
	const queue = new PQueue({ concurrency: MAX_INSTANCES })

	const browser = await puppeteer.launch({
		executablePath: '/usr/bin/google-chrome-stable',
		headless: true,
		args: ['--no-sandbox', '--disable-gpu']
	})

	console.log('Bot ready')
	while (true) {
		const { element: user } = await r.blPop('queue', 0)
		queue.add(() => visit(browser, user, Date.now()))
	}
})()
