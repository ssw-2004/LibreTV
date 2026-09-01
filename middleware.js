import { sha256 } from './js/sha256.js';

// EdgeOne Makers Middleware to inject environment variables
export async function middleware(context) {
  const { request, env, next } = context;

  // Get the URL from the request
  const url = new URL(request.url);

  // === 整站密码访问门禁 ===
  const password = env.PASSWORD || '';
  const passwordHash = password ? await sha256(password) : '';
  let authPassed = false;

  // a. 登录接口：POST /__auth__，表单字段 p（密码）、r（跳转地址）
  if (url.pathname === '/__auth__' && request.method === 'POST') {
    const formData = await request.formData();
    const p = (formData.get('p') || '').toString();
    let r = (formData.get('r') || '/').toString();
    // r 只允许以 '/' 开头的站内路径，否则回退 '/'
    if (!r.startsWith('/')) r = '/';

    // 未设置 PASSWORD：完全免密，直接放行
    if (!password) {
      return new Response(null, {
        status: 302,
        headers: { 'Location': r }
      });
    }

    const inputHash = await sha256(p);
    if (inputHash === passwordHash) {
      return new Response(null, {
        status: 302,
        headers: {
          'Location': r,
          'Set-Cookie': `libretv_auth=${inputHash}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax`
        }
      });
    }

    // 密码错误：返回登录页并提示
    return new Response(loginPage(r, true), {
      status: 401,
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }

  // Only process HTML pages
  const isHtmlPage = url.pathname.endsWith('.html') || url.pathname.endsWith('/');

  // b. HTML 门禁校验：设置了 PASSWORD 时必须携带合法 libretv_auth cookie
  if (isHtmlPage && password) {
    const cookies = parseCookies(request.headers.get('cookie') || '');
    if (cookies.get('libretv_auth') === passwordHash) {
      authPassed = true;
    } else {
      // 未通过门禁：返回内联登录页，登录成功后跳回当前 url.pathname+search
      const redirectTo = url.pathname + url.search;
      return new Response(loginPage(redirectTo, false), {
        status: 401,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }
  }

  // 非 HTML 请求直接放行
  if (!isHtmlPage) {
    return next();
  }

  // === 原有 HTML 注入逻辑 ===
  // Get the original response
  const response = await next();

  // Check if it's an HTML response
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('text/html')) {
    return response; // Return the original response if not HTML
  }

  // Get the HTML content
  const originalHtml = await response.text();

  // Replace the placeholder with actual environment variable
  // If PASSWORD is not set, replace with empty string
  const adminpassword = env.ADMINPASSWORD || '';
  let adminpasswordHash = '';
  if (adminpassword) {
    adminpasswordHash = await sha256(adminpassword);
  }

  // Merge the two replacements into one operation
  let modifiedHtml = originalHtml
    .replace(
      'window.__ENV__.PASSWORD = "{{PASSWORD}}";',
      `window.__ENV__.PASSWORD = "${passwordHash}"; // SHA-256 hash`
    )
    .replace(
      'window.__ENV__.ADMINPASSWORD = "{{ADMINPASSWORD}}";',
      `window.__ENV__.ADMINPASSWORD = "${adminpasswordHash}"; // SHA-256 hash`
    );

  // 已通过服务端门禁时，注入已认证标记，避免前端 js/password.js 重复弹出密码框
  if (password && authPassed) {
    const marker = '<script>window.__LIBRETV_AUTH_PASSED__ = true;</script>';
    if (modifiedHtml.includes('</body>')) {
      modifiedHtml = modifiedHtml.replace('</body>', marker + '</body>');
    } else {
      modifiedHtml += marker;
    }
  }

  // Return the modified response
  return new Response(modifiedHtml, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers
  });
}

export const config = {
  matcher: ['/', '/((?!api|_next/static|_vercel|favicon.ico).*)'],
};

// 解析 Cookie 请求头为 Map
function parseCookies(cookieHeader) {
  const map = new Map();
  if (!cookieHeader) return map;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    map.set(key, value);
  }
  return map;
}

// HTML 转义，防止隐藏字段 r 破坏页面结构
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// 内联登录页（简洁居中样式）
function loginPage(redirectTo, showError) {
  const notice = showError
    ? '<p class="error">密码错误，请重试</p>'
    : '<p class="tip">此站点受密码保护</p>';
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>请输入访问密码</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f1115;color:#e5e7eb;font-family:system-ui,-apple-system,"Segoe UI",Roboto,"PingFang SC",sans-serif;}
  .card{background:#1a1d24;border:1px solid #2a2e37;border-radius:12px;padding:40px 32px;width:320px;box-sizing:border-box;box-shadow:0 20px 60px rgba(0,0,0,.45);}
  h1{font-size:19px;margin:0 0 8px;text-align:center;}
  .tip{color:#9ca3af;font-size:13px;margin:0 0 20px;text-align:center;}
  .error{color:#f87171;font-size:14px;margin:0 0 16px;text-align:center;}
  input[type="password"]{width:100%;box-sizing:border-box;padding:12px 14px;border-radius:8px;border:1px solid #3a3f4b;background:#111318;color:#f3f4f6;font-size:15px;outline:none;}
  input[type="password"]:focus{border-color:#60a5fa;}
  button{width:100%;margin-top:16px;padding:12px;border:none;border-radius:8px;background:#2563eb;color:#fff;font-size:15px;font-weight:600;cursor:pointer;}
  button:hover{background:#1d4ed8;}
</style>
</head>
<body>
  <form class="card" method="POST" action="/__auth__">
    <h1>请输入访问密码</h1>
    ${notice}
    <input type="hidden" name="r" value="${escapeHtml(redirectTo)}">
    <input type="password" name="p" placeholder="密码" autofocus autocomplete="current-password">
    <button type="submit">进入</button>
  </form>
</body>
</html>`;
}
