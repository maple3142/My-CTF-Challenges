const site = new URL(atob(document.currentScript.getAttribute('data-siteb64')))
const siteBase = new URL(location.pathname.split('/').slice(0, 2).join('/') + '/', location.href)

let viewer = document.getElementById('viewer')

const plainTypes = ['text/plain', 'application/json']
const viewableTypes = plainTypes.concat(['text/html'])

const openExternal = url => {
	const u = new URL(url)
	if (u.protocol === 'http:' || u.protocol === 'https:') open(u.href, '_blank')
}

const loadContent = async (url, content, type = 'text/html') => {
	console.log('loadContent', url.href, type)
	if (plainTypes.some(t => type.startsWith(t))) {
		const datauri = `data:text/plain,` + encodeURIComponent(content)
		viewer.src = datauri
		return
	}
	if (!type.startsWith('text/html')) {
		alert('unsupported content type')
		return
	}
	const newViewer = document.createElement('iframe')
	viewer.replaceWith(newViewer)
	viewer = newViewer

	const doc = DOMPurify.sanitize(content, {
		RETURN_DOM: true,
		WHOLE_DOCUMENT: true,
		ADD_TAGS: ['link']
	})
	const resolveUrl = href =>
		href.startsWith('/') ? new URL(href.replace(/^\/+/, './/'), siteBase) : new URL(href, url)
	;[...doc.querySelectorAll('link[rel=stylesheet][href]')].map(e => {
		const href = e.getAttribute('href')
		e.setAttribute('href', resolveUrl(href))
	})
	;[...doc.querySelectorAll('img[src]')].map(e => {
		e.removeAttribute('srcset') // idk how to handle this
		const src = e.getAttribute('src')
		e.setAttribute('src', resolveUrl(src))
	})
	;[...doc.querySelectorAll('picture source')].forEach(e => e.remove()) // idk how to handle this either
	;[...doc.querySelectorAll('link:not([rel=stylesheet])')].forEach(e => e.remove()) // say goodbye to anything else to remove unnecessary requests
	;[...doc.querySelectorAll('a[href]')].forEach(e => {
		// handle links
		let href = e.getAttribute('href')
		try {
			const u = new URL(href)
			if (u.origin !== site.origin) {
				// is absolute, and not same origin, treat as external link
				e.setAttribute('target', '_blank')
				return
			} else {
				// is absolute, but same origin, convert to relative
				href = u.pathname + u.search + u.hash
			}
		} catch {}
		const newUrl = resolveUrl(href)
		e.setAttribute('href', newUrl)
		e.addEventListener('click', e => {
			e.preventDefault()
			history.pushState({}, '', newUrl)
			if (newUrl.hash && href.startsWith('#')) {
				// fast anchor handling
				const el = viewer.contentDocument.querySelector(decodeURIComponent(newUrl.hash))
				el?.scrollIntoView()
				return
			}
			load(newUrl)
		})
	})
	;[...doc.querySelectorAll('form')].forEach(e => {
		// handle forms
		e.addEventListener('submit', e => {
			e.preventDefault()
			const options = {
				method: e.target.method.toUpperCase(),
				headers: {
					'x-requested-from': location.href
				}
			}
			if (options.method === 'POST') {
				if (e.target.enctype.toLowerCase() === 'multipart/form-data') {
					options.body = new FormData(e.target)
					options.headers['content-type'] = 'multipart/form-data'
				} else if (e.target.enctype.toLowerCase() === 'application/x-www-form-urlencoded') {
					options.body = new URLSearchParams(new FormData(e.target)).toString()
					options.headers['content-type'] = 'application/x-www-form-urlencoded'
				} else {
					alert('form submission failed, unsupported form enctype')
					throw new Error('unsupported form enctype')
				}
			}
			const url = resolveUrl(e.target.getAttribute('action') || url.href)
			fetch(url, options).then(r => {
				const type = r.headers.get('content-type') || 'text/plain'
				if (viewableTypes.some(t => type.startsWith(t))) {
					history.pushState({}, '', r.url)
					return r.text().then(content => loadContent(new URL(r.url), content, type))
				} else {
					openExternal(r.headers.get('x-location') || r.headers.get('x-target-url'))
				}
			})
		})
	})

	// all done, replace the iframe content
	viewer.contentDocument.documentElement.replaceWith(doc)
	document.title = viewer.contentDocument.title

	// scroll to anchor once loaded
	if (url.hash) {
		await new Promise(resolve => setTimeout(resolve, 500)) // not sure how to detect if reflow is done :(
		const el = viewer.contentDocument.querySelector(decodeURIComponent(url.hash))
		el?.scrollIntoView()
	}
}
const load = url => {
	console.log('load', url.href)
	fetch(url)
		.then(r => {
			const type = r.headers.get('content-type') || 'text/plain'
			if (viewableTypes.some(t => type.startsWith(t))) {
				return r.text().then(content => loadContent(url, content, type))
			} else {
				history.back()
				openExternal(r.headers.get('x-location') || r.headers.get('x-target-url'))
			}
		})
		.catch(e => {
			console.error('fetch error', e)
		})
}
window.addEventListener('popstate', e => {
	load(new URL(location.href))
})
load(new URL(location.href))
