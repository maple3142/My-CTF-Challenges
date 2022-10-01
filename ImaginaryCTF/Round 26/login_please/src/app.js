const express = require('express')
const crypto = require('crypto')

function md5(text) {
	return crypto.createHash('md5').update(text).digest('hex')
}

const app = express()

const users = {
	guest: '084e0343a0486ff05530df6c705c8bb4',
	admin: '21232f297a57a5a743894a0e4a801fc3',
	'1337hacker': '2ab96390c7dbe3439de74d0c9b0b1767'
}
const localIPs = ['127.0.0.1', '::1', '::ffff:127.0.0.1']

app.use(express.urlencoded({ extended: false }))
app.use(express.json())
app.get('/', (req, res) => {
	res.end(`
<form action="/login" method="POST">
    <div>
        <label for="username">Username: </label>
        <input name="username" type="text" id="username">
    </div>
    <div>
        <label for="password">Password: </label>
        <input name="password" type="password" id="password">
    </div>
    <button type="submit">Login</button>
</form>
<!-- /source -->
`)
})

app.post('/login', (req, res) => {
	if (req.body.username === 'admin' && !localIPs.includes(req.ip)) {
		return res.end('Admin is only allowed from localhost')
	}
	const auth = Object.assign({}, req.body)
	if (users[auth.username] === md5(auth.password)) {
		if (auth.username === 'admin') {
			res.end(`Welcome admin! The flag is ${process.env.FLAG}`)
		} else {
			res.end(`Welcome ${auth.username}!`)
		}
	} else {
		res.end('Invalid username or password')
	}
})

app.get('/source', (req, res) => {
	res.sendFile(__filename)
})

app.get('/package.json', (req, res) => {
	res.sendFile('package.json', { root: __dirname })
})

const port = 1337 || process.env.PORT
app.listen(port, () => {
	console.log(`Server running on http://localhost:${port}`)
})
