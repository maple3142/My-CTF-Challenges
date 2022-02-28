// rendering notes
const container = document.getElementById('notes-container')
function createNote(note) {
	const el = document.importNode(document.getElementById('note-tmpl').content, true)
	el.querySelector('.note-title').textContent = note.title
	el.querySelector('.note-author').textContent = note.author
	el.querySelector('.note-content').innerHTML = DOMPurify.sanitize(marked.parse(note.content))
	return el
}
function loadNotes() {
	container.textContent = ''
	fetch('/api/notes' + location.search)
		.then(r => r.json())
		.then(notes => {
			container.append(...notes.map(createNote))
		})
}

// submitting notes
const titleEl = document.getElementById('title')
const contentEl = document.getElementById('content')
function trySubmit() {
	const title = titleEl.value
	const content = contentEl.value
	if (title && content) {
		fetch('/api/notes', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ title, content })
		})
			.then(r => r.json())
			.then(r => {
				if (r.status === 'ok') {
					titleEl.value = ''
					contentEl.value = ''
					loadNotes()
				} else {
					alert(r.msg)
				}
			})
	}
}
const addBtn = document.getElementById('add-btn')
addBtn.addEventListener('click', trySubmit)

// logout btn
function logout() {
	document.getElementById('logout-form').submit()
}
const logoutBtn = document.getElementById('logout-btn')
logoutBtn.addEventListener('click', logout)

// share to admin btn
function tokenCallback(token) {
	fetch('/api/share', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ token })
	})
		.then(r => r.json())
		.then(r => {
			if (r.status === 'ok') {
				alert('Admin will view your note later!')
			} else {
				alert('Sorry, you need to pass recaptcha')
			}
		})
}
function share() {
	grecaptcha.execute()
}
const shareBtn = document.getElementById('share-btn')
shareBtn.addEventListener('click', share)

// init
loadNotes()
