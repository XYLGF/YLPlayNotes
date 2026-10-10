// ============================================================
// YL Note · 独立云笔记后端
// ============================================================

// 工具：密码哈希
async function hashPassword(password, salt) {
  const encoder = new TextEncoder();
  const data = encoder.encode(salt + ':' + password);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// 工具：生成 token
function generateToken() {
  return crypto.randomUUID() + '-' + Date.now().toString(36);
}

// 工具：JSON 响应
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...headers
    }
  });
}

// 工具：验证 token，返回 user 或 null
async function authUser(env, token) {
  if (!token) return null;
  const user = await env.DB.prepare('SELECT id, username FROM users WHERE token = ?').bind(token).first();
  return user || null;
}

// ============================================================
// 主入口
// ============================================================
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (method === 'OPTIONS') return new Response(null, { headers: cors });

    // 非 API → 静态资源
    if (!path.startsWith('/api/')) {
      if (path.includes('.')) return env.ASSETS.fetch(request);
      const indexUrl = new URL(request.url);
      indexUrl.pathname = '/note.html';
      return env.ASSETS.fetch(new Request(indexUrl, request));
    }

    try {
      // ========================================================
      // 注册
      // ========================================================
      if (path === '/api/register' && method === 'POST') {
        const { username, password } = await request.json();
        if (!username || !password) return json({ success: false, message: '用户名和密码不能为空' }, 400, cors);
        if (username.length < 2 || username.length > 20) return json({ success: false, message: '用户名长度 2-20 位' }, 400, cors);
        if (password.length < 4) return json({ success: false, message: '密码至少 4 位' }, 400, cors);
        if (!/^[\w\u4e00-\u9fa5]{2,20}$/.test(username)) return json({ success: false, message: '用户名只能包含字母/数字/下划线/中文' }, 400, cors);

        const exist = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
        if (exist) return json({ success: false, message: '用户名已被注册' }, 409, cors);

        const salt = crypto.randomUUID();
        const hashed = await hashPassword(password, salt);
        const now = Date.now();
        await env.DB.prepare(
          'INSERT INTO users (username, password, salt, created_at) VALUES (?, ?, ?, ?)'
        ).bind(username, hashed, salt, now).run();

        return json({ success: true, message: '注册成功' }, 200, cors);
      }

      // ========================================================
      // 登录
      // ========================================================
      if (path === '/api/login' && method === 'POST') {
        const { username, password } = await request.json();
        if (!username || !password) return json({ success: false, message: '用户名和密码不能为空' }, 400, cors);

        const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
        if (!user) return json({ success: false, message: '用户不存在' }, 404, cors);

        const hashed = await hashPassword(password, user.salt);
        if (hashed !== user.password) return json({ success: false, message: '密码错误' }, 401, cors);

        const token = generateToken();
        await env.DB.prepare('UPDATE users SET token = ? WHERE id = ?').bind(token, user.id).run();

        return json({
          success: true,
          user: { id: user.id, username: user.username },
          token
        }, 200, cors);
      }

      // ========================================================
      // 验证 token
      // ========================================================
      if (path === '/api/verify' && method === 'POST') {
        const { token } = await request.json();
        const user = await authUser(env, token);
        if (!user) return json({ success: false, message: '登录失效' }, 401, cors);
        return json({ success: true, user }, 200, cors);
      }

      // ========================================================
      // 笔记列表
      // ========================================================
      if (path === '/api/notes' && method === 'POST') {
        const { token } = await request.json();
        const user = await authUser(env, token);
        if (!user) return json({ success: false, message: '登录失效' }, 401, cors);

        const { results } = await env.DB.prepare(
          'SELECT * FROM notes WHERE user_id = ? ORDER BY updated_at DESC'
        ).bind(user.id).all();

        return json({ success: true, notes: results }, 200, cors);
      }

      // ========================================================
      // 保存笔记（新建/更新）
      // ========================================================
      if (path === '/api/notes/save' && method === 'POST') {
        const { token, id, title, content } = await request.json();
        const user = await authUser(env, token);
        if (!user) return json({ success: false, message: '登录失效' }, 401, cors);

        const now = Date.now();
        if (id) {
          const exist = await env.DB.prepare('SELECT id FROM notes WHERE id = ? AND user_id = ?').bind(id, user.id).first();
          if (!exist) return json({ success: false, message: '笔记不存在' }, 404, cors);
          await env.DB.prepare(
            'UPDATE notes SET title = ?, content = ?, updated_at = ? WHERE id = ? AND user_id = ?'
          ).bind(title || '', content || '', now, id, user.id).run();
          return json({ success: true, id }, 200, cors);
        } else {
          const result = await env.DB.prepare(
            'INSERT INTO notes (user_id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
          ).bind(user.id, title || '', content || '', now, now).run();
          return json({ success: true, id: result.meta.last_row_id }, 200, cors);
        }
      }

      // ========================================================
      // 删除笔记
      // ========================================================
      if (path === '/api/notes/delete' && method === 'POST') {
        const { token, id } = await request.json();
        const user = await authUser(env, token);
        if (!user) return json({ success: false, message: '登录失效' }, 401, cors);
        if (!id) return json({ success: false, message: '参数缺失' }, 400, cors);

        await env.DB.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?').bind(id, user.id).run();
        return json({ success: true }, 200, cors);
      }

      return json({ success: false, message: 'Not Found' }, 404, cors);

    } catch (e) {
      return json({ success: false, message: e.message }, 500, cors);
    }
  }
};