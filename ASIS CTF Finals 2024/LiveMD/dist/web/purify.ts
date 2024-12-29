import DOMPurify from 'dompurify'

let purify
if (import.meta.server) {
	const { JSDOM } = await import('jsdom')
	const window = new JSDOM('').window
	purify = DOMPurify(window)
} else {
	purify = DOMPurify
}
purify.addHook('uponSanitizeAttribute', (currentNode, event, config) => {
	event.keepAttr = false
	try {
		if (event.attrName === 'src' || event.attrName === 'href') {
			if (URL.canParse(event.attrValue)) {
				// absolute URL
				event.attrValue = new URL(event.attrValue).href
			} else {
				// relative URL
				const u = new URL(event.attrValue, import.meta.server ? 'http://localhost' : document.baseURI)
				event.attrValue = u.pathname + u.search + u.hash
			}
			event.keepAttr = true
		}
	} catch {}
})
export const sanitize = (html: string) => purify.sanitize(html)
