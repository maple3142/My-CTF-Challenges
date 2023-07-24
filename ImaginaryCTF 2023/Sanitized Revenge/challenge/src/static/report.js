const frm = document.getElementById('report-form')
frm.addEventListener('submit', e => {
	e.preventDefault()
	fetch('/report', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			html: document.getElementById('html-input').value
		})
	})
		.then(r => r.json())
		.then(resp => {
			if (resp.error) {
				alert(resp.error)
			} else {
				alert(resp.message)
			}
		})
})
