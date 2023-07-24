const params = new URLSearchParams(location.search)
const html = params.get('html')
if (html) {
	document.getElementById('html').value = html
	document.getElementById('display').innerHTML = DOMPurify.sanitize(html)
}
