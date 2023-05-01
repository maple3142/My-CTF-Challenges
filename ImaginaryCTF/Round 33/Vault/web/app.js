window.onload = () => {
	ta.value = localStorage.getItem('secret')
}
btn.onclick = () => {
	localStorage.setItem('secret', ta.value)
}
frm.onsubmit = () => {
	frm.action += '?url=' + encodeURIComponent(frm.url.value)
}
