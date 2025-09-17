const state = {
	user: null,
	users: [],
	activeUserId: null,
	socket: null,
};

function $(id) { return document.getElementById(id); }
function show(elId) { $(elId).classList.remove('hidden'); }
function hide(elId) { $(elId).classList.add('hidden'); }

function formatTime(ts) {
	try { return new Date(ts).toLocaleTimeString(); } catch { return ''; }
}

async function api(path, options = {}) {
	const res = await fetch(path, {
		credentials: 'include',
		headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
		...options,
		body: options.body && typeof options.body !== 'string' ? JSON.stringify(options.body) : options.body,
	});
	if (!res.ok) throw new Error((await res.json()).error || 'request failed');
	return res.json();
}

async function tryRestoreSession() {
	try {
		const { user } = await api('/api/me');
		state.user = user;
		onAuth();
	} catch {}
}

function onAuth() {
	$('me-name').textContent = state.user.username;
	
	// Показать админ-элементы если пользователь админ
	if (state.user.is_admin) {
		$('admin-badge').classList.remove('hidden');
		$('admin-btn').classList.remove('hidden');
	}
	
	hide('auth'); hide('register'); show('chat');
	loadUsers();
	connectSocket();
}

async function loadUsers() {
	const { users } = await api('/api/users');
	state.users = users;
	renderUsers();
	if (!state.activeUserId && users.length) {
		selectUser(users[0].id);
	}
}

function renderUsers() {
	const ul = $('users-list');
	ul.innerHTML = '';
	for (const u of state.users) {
		const li = document.createElement('li');
		li.textContent = u.username;
		li.dataset.userId = u.id;
		if (u.id === state.activeUserId) li.classList.add('active');
		li.onclick = () => selectUser(u.id);
		ul.appendChild(li);
	}
}

async function selectUser(userId) {
	state.activeUserId = userId;
	renderUsers();
	const { messages } = await api(`/api/messages/${userId}`);
	renderMessages(messages);
}

function renderMessages(messages) {
	const box = $('conversation');
	box.innerHTML = '';
	for (const m of messages) {
		appendMessage(m);
	}
	box.scrollTop = box.scrollHeight;
}

function getUsernameById(userId) {
	if (userId === state.user?.id) return state.user.username;
	const u = state.users.find(x => x.id === userId);
	return u ? u.username : `ID ${userId}`;
}

function appendMessage(m) {
	const box = $('conversation');
	const me = m.sender_id === state.user.id;
	const div = document.createElement('div');
	div.className = `msg ${me ? 'me' : 'other'}`;

	const author = document.createElement('div');
	author.className = 'author';
	author.textContent = getUsernameById(m.sender_id);
	div.appendChild(author);

	if (m.content) {
		const p = document.createElement('div');
		p.textContent = m.content;
		div.appendChild(p);
	}
	if (m.file_url) {
		if (m.file_url.match(/\.(png|jpg|jpeg|gif|webp)$/i)) {
			const img = document.createElement('img');
			img.src = m.file_url;
			img.className = 'message-image';
			div.appendChild(img);
		} else {
			const a = document.createElement('a');
			a.href = m.file_url;
			a.textContent = 'Файл';
			a.className = 'file-link';
			a.target = '_blank';
			div.appendChild(a);
		}
	}
	const meta = document.createElement('div');
	meta.className = 'meta';
	meta.textContent = formatTime(m.created_at);
	div.appendChild(meta);
	box.appendChild(div);
}

function connectSocket() {
	if (state.socket) {
		state.socket.disconnect();
		state.socket = null;
	}
	state.socket = io('/');
	state.socket.on('connect', () => {});
	state.socket.on('direct_message', (m) => {
		if (m.sender_id === state.activeUserId || m.recipient_id === state.activeUserId) {
			appendMessage(m);
			const box = $('conversation');
			box.scrollTop = box.scrollHeight;
		}
	});
}

async function handleSend() {
	if (!state.activeUserId) return;
	const input = $('message-input');
	const fileInput = $('file-input');
	let fileUrl = null;
	if (fileInput.files && fileInput.files[0]) {
		const form = new FormData();
		form.append('file', fileInput.files[0]);
		const res = await fetch('/api/upload', { method: 'POST', body: form, credentials: 'include' });
		if (!res.ok) { alert('Ошибка загрузки файла'); return; }
		fileUrl = (await res.json()).fileUrl;
		fileInput.value = '';
	}
	const content = input.value.trim();
	if (!content && !fileUrl) return;
	state.socket.emit('direct_message', { toUserId: state.activeUserId, content, fileUrl }, (ack) => {
		if (ack?.ok && ack.message) {
			appendMessage(ack.message);
			const box = $('conversation');
			box.scrollTop = box.scrollHeight;
			input.value = '';
		}
	});
}

// Event bindings
$('login-btn').onclick = async () => {
	try {
		const username = $('login-username').value.trim();
		const password = $('login-password').value;
		const { user } = await api('/api/login', { method: 'POST', body: { username, password } });
		state.user = user; onAuth();
	} catch (e) { alert(e.message); }
};

$('register-btn').onclick = async () => {
	try {
		const username = $('register-username').value.trim();
		const password = $('register-password').value;
		const { user } = await api('/api/register', { method: 'POST', body: { username, password } });
		state.user = user; onAuth();
	} catch (e) { alert(e.message); }
};

$('to-register').onclick = () => { hide('auth'); show('register'); };
$('to-login').onclick = () => { hide('register'); show('auth'); };
$('logout-btn').onclick = async () => { await api('/api/logout', { method: 'POST' }); location.reload(); };
$('send-btn').onclick = handleSend;
$('message-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') handleSend(); });

// Админ-панель
$('admin-btn').onclick = () => {
	hide('chat');
	show('admin-panel');
	loadAdminData();
};

$('back-to-chat-btn').onclick = () => {
	hide('admin-panel');
	show('chat');
};

async function loadAdminData() {
	try {
		const [usersRes, statsRes] = await Promise.all([
			api('/api/admin/users'),
			api('/api/admin/stats')
		]);
		
		// Загрузить статистику
		$('total-users').textContent = statsRes.stats.total_users;
		$('total-messages').textContent = statsRes.stats.total_messages;
		$('messages-today').textContent = statsRes.stats.messages_today;
		
		// Загрузить таблицу пользователей
		const tbody = $('admin-users-list');
		tbody.innerHTML = '';
		
		for (const user of usersRes.users) {
			const row = document.createElement('tr');
			row.innerHTML = `
				<td>${user.id}</td>
				<td>${user.username}</td>
				<td><span class="${user.is_admin ? 'admin-status' : 'user-status'}">${user.is_admin ? 'Админ' : 'Пользователь'}</span></td>
				<td>${user.message_count}</td>
				<td>${new Date(user.created_at).toLocaleDateString()}</td>
			`;
			tbody.appendChild(row);
		}
	} catch (e) {
		alert('Ошибка загрузки админ-данных: ' + e.message);
	}
}

tryRestoreSession(); 