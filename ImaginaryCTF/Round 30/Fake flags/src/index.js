;(() => {
	function rc4(key, str) {
		var s = [],
			j = 0,
			x,
			res = ''
		for (var i = 0; i < 256; i++) {
			s[i] = i
		}
		for (i = 0; i < 256; i++) {
			j = (j + s[i] + key.charCodeAt(i % key.length)) % 256
			x = s[i]
			s[i] = s[j]
			s[j] = x
		}
		i = 0
		j = 0
		for (var y = 0; y < str.length; y++) {
			i = (i + 1) % 256
			j = (j + s[i]) % 256
			x = s[i]
			s[i] = s[j]
			s[j] = x
			res += String.fromCharCode(str.charCodeAt(y) ^ s[(s[i] + s[j]) % 256])
		}
		return res
	}
	function flag2el(flag) {
		const div = document.createElement('div')
		for (const c of flag) {
			const span = document.createElement('span')
			span.innerText = c + '\u200c'
			for (let k = 0; k < 10; k++) {
				span.classList.add(randstring(10))
			}
			div.appendChild(span)
			const span2 = document.createElement('span')
			span2.innerText = c + '\u200c'
			span2.style.position = 'absolute'
			span2.style.left = '-9999px'
			for (let k = 0; k < 10; k++) {
				span2.classList.add(randstring(10))
			}
			div.appendChild(span2)
		}
		return div
	}
	function randrange(a, b) {
		return Math.floor(Math.random() * (b - a)) + a
	}
	function randstring(len) {
		var text = ''
		var possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-'
		for (var i = 0; i < len; i++) text += possible.charAt(Math.floor(Math.random() * possible.length))
		return text
	}
	const s = atob(
		'GtbaluedlQjKxqhv1+JtSQQd4fKNCaXOIZd8F9br5CTZxyopgeYzxJEOBJZnvWw3GfbSLQmB2EqSIA78qd/vSVLNaD4QMhXF5RbeTy6eum8cblU1rClQhvm46/oYP1gbCXoBQpGOQfinahfSkF1WjpiVNqWpOW0FX8rKg9dBJpkSioS4KlSjyQ34Nu+D07w8+VAmTAyHqFPG/aR40eXzUdbRVynp1ju2b34tSM5x2ubwbTHHqKxUilOc8nUoEzenGtc96gTzSWmFj3T8gPL4UykKodHe9UGIBptJem56jwKC0/KPlIs+i/NibHydkx+kA1/nOUQIqq8/q7/f7ZHwgWTv8F3LsaF7bW1p7wuyjTU3T/fQKRXq/XJddKgnUjbiZW+FRnLelKpPDWctR0Tqn1ls9F7uzzYKuv2HoQVzW6/A4D0tucw1sdx+fTbYGe3fblaP8BywJfQ+KxT/jKAOVNO11mjKM5R7a3g4IeBroltGXw1BHts1bfnKkJLsF+znpg5/Gt99LfT5BuNfBTsRUH0RZbk38j0SoQVP0c0Lr6op0Zht4vYLKus4XllSZKH243JgHRR8fEf/WgV8kwPcVpFvN5KCz+YHqEyNEJMJifI1xu8XO1J/f9p4lF0YAc9pU2clVU5p9NVzsfhRLETTq5ckubfPTJBfVss6f4Slom9SND2RPnPXVDw7FlxdfnUSrKBGFU6ij2mnRcgnhyMxbe1QJljGEtiVDfauwvvNF7Vz53wNW2ptqF2Cl1WgPp6rungHzJBTFANXA81kqQhJKWjyoLQBwXNxTpZBd2sCvb7HmU5h1/SdpiIe6sSsHsDZdKrEMl7ZKPWPKZgRpDAVuZ/Dc4eTcy03GbwnqZMXpInNuyW+RZwwGQx+dw1nFt7lZOMi2wViPoBr3HFfEdFpzioBG2jCcQtVAVjYSOM3TT1XnD93O/4EjB7py3ULCFWkmaqJdqTBvv6yUvsdOtUCVYvfLCDytcKer5LKZV6rAxh3z/rLT/S39zVVNoRZEldOR0g='
	)
	const els = (() => {
		const flags = rc4(document.getElementsByTagName('style')[0].textContent, s).split(',')
		if (flags.length != 17) {
			alert('Integrity error')
			return
		}
		const els = []
		for (let i = 0; i < 1024; i++) {
			const j = randrange(0, flags.length - 1)
			const el = flag2el(flags[i == 666 ? flags.length - 1 : j])
			for (let k = 0; k < 10; k++) {
				el.classList.add(randstring(10))
			}
			if (randrange(0, 3) == 0 || j == flags.length - 1) {
				el.classList.add('ads-banner')
			}
			for (let k = 0; k < 10; k++) {
				el.classList.add(randstring(10))
			}
			el.style.animationDelay = randrange(0, 1000) + 'ms'
			document.body.appendChild(el)
			els.push(el)
		}
		return els
	})()
	const cursors = ['wait', 'progress', 'crosshair', 'pointer', 'move', 'text', 'not-allowed', 'grab', 'grabbing']
	setInterval(() => {
		for (const el of els) {
			el.style.color = '#' + randrange(0x000000, 0xffffff).toString(16).padStart(6, '0')
		}
		document.body.style.cursor = cursors[randrange(0, cursors.length)]
		eval('debugger;')
	}, 1000)
	onclick = () => {
		location.href = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ'
	}
	onload = () => {
		document.body.oncopy = e => {
			e.clipboardData.setData('text/plain', flags[0])
			e.preventDefault()
		}
	}
})()
