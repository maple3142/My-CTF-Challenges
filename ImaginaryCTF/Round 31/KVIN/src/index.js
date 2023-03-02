#!/usr/bin/env node
const readline = require('readline')
const KVIN = require('kvin')

function input(rl, prompt) {
	return new Promise(resolve => rl.question(prompt, resolve))
}

function safeParse(s) {
	return KVIN.unmarshal(
		JSON.parse(s, (k, v) => {
			if (k === 'ctr' && typeof v !== 'number') {
				// custom constructors are too dangerous...
				v = 0
			}
			return v
		})
	)
}

const rl = readline.createInterface({
	input: process.stdin,
	output: process.stderr,
	terminal: false
})
input(rl, 'JSON: ')
	.then(safeParse)
	.then(console.log)
	.catch(console.error)
	.finally(() => rl.close())
