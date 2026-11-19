const CORS_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8'
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: CORS_HEADERS
  });
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function randomHex(bytes = 16) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function normalizeUsername(raw) {
  return String(raw || '').trim().toLowerCase();
}

function validateUsername(u) {
  return /^[a-z0-9_.-]{3,32}$/.test(u);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith('/api/')) {
      if (!env.DB) {
        return jsonResponse({ error: 'База данных D1 (binding DB) не подключена' }, 500);
      }

      try {
        // Регистрация
        if (url.pathname === '/api/register' && request.method === 'POST') {
          const body = await request.json();
          const username = normalizeUsername(body.username);
          const password = String(body.password || '');

          if (!validateUsername(username)) {
            return jsonResponse(
              { error: 'Логин: 3–32 символа (латиница, цифры, ., _, -)' },
              400
            );
          }
          if (password.length < 4) {
            return jsonResponse({ error: 'Пароль должен быть не короче 4 символов' }, 400);
          }

          const existing = await env.DB
            .prepare('SELECT id FROM users WHERE username = ?')
            .bind(username)
            .first();

          if (existing) {
            return jsonResponse({ error: 'Такой логин уже занят' }, 409);
          }

          const salt = randomHex(16);
          const passwordHash = await sha256Hex(`${salt}:${password}`);
          const now = new Date().toISOString();

          const insertRes = await env.DB
            .prepare('INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)')
            .bind(username, passwordHash, salt, now)
            .run();

          const userId = insertRes.meta.last_row_id;

          return jsonResponse({
            user: { id: userId, username },
            state: null
          });
        }

        // Вход
        if (url.pathname === '/api/login' && request.method === 'POST') {
          const body = await request.json();
          const username = normalizeUsername(body.username);
          const password = String(body.password || '');

          if (!username || !password) {
            return jsonResponse({ error: 'Введите логин и пароль' }, 400);
          }

          const user = await env.DB
            .prepare('SELECT id, username, password_hash, salt FROM users WHERE username = ?')
            .bind(username)
            .first();

          if (!user) {
            return jsonResponse({ error: 'Неверный логин или пароль' }, 401);
          }

          const checkHash = await sha256Hex(`${user.salt}:${password}`);
          if (checkHash !== user.password_hash) {
            return jsonResponse({ error: 'Неверный логин или пароль' }, 401);
          }

          const savedRow = await env.DB
            .prepare('SELECT state_json, updated_at FROM user_states WHERE user_id = ?')
            .bind(user.id)
            .first();

          return jsonResponse({
            user: { id: user.id, username: user.username },
            state: savedRow ? JSON.parse(savedRow.state_json) : null,
            updatedAt: savedRow ? savedRow.updated_at : null
          });
        }

        // Получение сохранённого состояния аккаунта
        if (url.pathname === '/api/state' && request.method === 'GET') {
          const username = normalizeUsername(url.searchParams.get('username'));
          if (!username) {
            return jsonResponse({ error: 'Не указан пользователь' }, 400);
          }

          const user = await env.DB
            .prepare('SELECT id, username FROM users WHERE username = ?')
            .bind(username)
            .first();

          if (!user) {
            return jsonResponse({ error: 'Пользователь не найден' }, 404);
          }

          const savedRow = await env.DB
            .prepare('SELECT state_json, updated_at FROM user_states WHERE user_id = ?')
            .bind(user.id)
            .first();

          return jsonResponse({
            state: savedRow ? JSON.parse(savedRow.state_json) : null,
            updatedAt: savedRow ? savedRow.updated_at : null
          });
        }

        // Сохранение / синхронизация состояния аккаунта
        if (url.pathname === '/api/state' && request.method === 'POST') {
          const body = await request.json();
          const username = normalizeUsername(body.username);
          const state = body.state;

          if (!username || !state || typeof state !== 'object') {
            return jsonResponse({ error: 'Некорректные данные синхронизации' }, 400);
          }

          const user = await env.DB
            .prepare('SELECT id FROM users WHERE username = ?')
            .bind(username)
            .first();

          if (!user) {
            return jsonResponse({ error: 'Аккаунт не найден' }, 404);
          }

          const now = new Date().toISOString();
          const stateJson = JSON.stringify(state);

          await env.DB
            .prepare(`
              INSERT INTO user_states (user_id, state_json, updated_at)
              VALUES (?, ?, ?)
              ON CONFLICT(user_id) DO UPDATE SET
                state_json = excluded.state_json,
                updated_at = excluded.updated_at
            `)
            .bind(user.id, stateJson, now)
            .run();

          return jsonResponse({ ok: true, updatedAt: now });
        }

        return jsonResponse({ error: 'Маршрут не найден' }, 404);
      } catch (err) {
        return jsonResponse({ error: 'Ошибка сервера: ' + err.message }, 500);
      }
    }

    // Отдача статических файлов (index.html и др.)
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response('Not Found', { status: 404 });
  }
};
