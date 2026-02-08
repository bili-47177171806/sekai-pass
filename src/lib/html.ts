export const styles = `
  :root {
    --bg-color: #0b0b0e;
    --card-bg: #17171c;
    --primary-color: #a48cd6;
    --primary-hover: #bda6e8;
    --text-main: #e2e2e6;
    --text-muted: #75757a;
    --border-color: #2a2a30;
    --input-bg: #111114;
    --error-color: #e57373;
    --success-color: #81c784;
    --code-font: 'Menlo', 'Monaco', 'Courier New', monospace;
  }

  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background-color: var(--bg-color);
    background-image: 
      linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-main);
  }

  .container {
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 8px; /* Slightly boxier, Niigo style */
    padding: 42px;
    width: 90%;
    max-width: 420px;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
    position: relative;
    overflow: hidden;
  }

  /* Decorative top line */
  .container::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 3px;
    background: linear-gradient(90deg, #594483, #a48cd6, #594483);
  }

  .logo {
    text-align: center;
    margin-bottom: 32px;
    position: relative;
  }
  
  /* Glitch effect decoration for logo area */
  .logo::after {
    content: 'SEKAI PASS // SYSTEM';
    display: block;
    font-family: var(--code-font);
    font-size: 10px;
    color: var(--text-muted);
    letter-spacing: 2px;
    margin-top: 12px;
    opacity: 0.6;
  }

  .logo img {
    max-width: 100%;
    height: auto;
    border-radius: 4px;
    /* Blend mode magic if background doesn't match perfectly */
    mix-blend-mode: normal; 
    margin: 0 auto;
    display: block;
  }

  .form-group {
    margin-bottom: 24px;
  }

  label {
    display: block;
    margin-bottom: 8px;
    font-size: 12px;
    color: var(--text-muted);
    font-family: var(--code-font);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  input {
    width: 100%;
    padding: 14px 16px;
    background: var(--input-bg);
    border: 1px solid var(--border-color);
    border-radius: 4px; /* Boxier for digital feel */
    color: var(--text-main);
    font-size: 14px;
    font-family: 'Inter', monospace; /* Tech feel */
    transition: border-color 0.2s, box-shadow 0.2s;
  }

  input:focus {
    outline: none;
    border-color: var(--primary-color);
    box-shadow: 0 0 0 2px rgba(164, 140, 214, 0.15);
  }

  input::placeholder {
    color: rgba(255, 255, 255, 0.2);
  }

  button {
    width: 100%;
    padding: 14px 16px;
    background: var(--primary-color);
    color: #1a1a1e;
    border: none;
    border-radius: 4px;
    font-size: 14px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    cursor: pointer;
    transition: all 0.2s;
    margin-top: 12px;
    position: relative;
    overflow: hidden;
  }

  button:hover {
    background: var(--primary-hover);
    transform: translateY(-1px);
    box-shadow: 0 4px 20px rgba(164, 140, 214, 0.3);
  }
  
  button:active {
    transform: translateY(0);
  }

  .error {
    background: rgba(229, 115, 115, 0.1);
    border-left: 3px solid var(--error-color);
    color: var(--error-color);
    padding: 12px 16px;
    margin-bottom: 24px;
    font-size: 13px;
    font-family: var(--code-font);
  }
  
  .success {
    background: rgba(129, 199, 132, 0.1);
    border-left: 3px solid var(--success-color);
    color: var(--success-color);
    padding: 12px 16px;
    margin-bottom: 24px;
    font-size: 13px;
    font-family: var(--code-font);
  }

  .link {
    text-align: center;
    margin-top: 32px;
    font-size: 13px;
    color: var(--text-muted);
  }

  .link a {
    color: var(--text-muted);
    text-decoration: underline;
    text-underline-offset: 4px;
    transition: color 0.2s;
  }

  .link a:hover {
    color: var(--primary-color);
  }
  
  /* Authorize Page */
  .auth-header {
    text-align: center;
    margin-bottom: 30px;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 24px;
  }

  .app-icon {
    width: 64px;
    height: 64px;
    background: #2a2a30;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 24px;
    color: var(--primary-color);
    margin: 0 auto 16px;
    border: 1px solid var(--border-color);
  }

  .auth-title {
    font-size: 18px;
    font-weight: 600;
    margin-bottom: 6px;
  }

  .user-badge {
    background: #202025;
    padding: 6px 12px;
    border-radius: 4px;
    font-size: 12px;
    font-family: var(--code-font);
    color: var(--text-muted);
    border: 1px solid var(--border-color);
    display: inline-block;
    margin-top: 12px;
  }

  .permission-box {
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    padding: 20px;
    margin-bottom: 24px;
  }
  
  .authorize-actions {
    display: grid;
    gap: 12px;
    grid-template-columns: 1fr 1fr;
  }
  
  .btn-secondary {
    background: transparent;
    border: 1px solid var(--border-color);
    color: var(--text-muted);
  }
  
  .btn-secondary:hover {
    background: rgba(255,255,255,0.05);
    color: var(--text-main);
    box-shadow: none;
  }

  .privacy-note {
    text-align: center;
    margin-top: 24px;
    font-size: 11px;
    color: rgba(255, 255, 255, 0.2);
    line-height: 1.6;
  }
  
  /* User info dashboard */
  .user-info {
    border: 1px solid var(--border-color);
    border-radius: 4px;
    padding: 0;
    margin-bottom: 30px;
    background: #00000020;
  }
  
  .user-info p {
    display: flex;
    justify-content: space-between;
    padding: 16px;
    border-bottom: 1px solid var(--border-color);
    margin: 0;
    font-size: 14px;
  }
  
  .user-info p:last-child {
    border-bottom: none;
  }
  
  .user-info strong {
    font-family: var(--code-font);
    font-size: 12px;
    color: var(--text-muted);
    text-transform: uppercase;
  }
`;

export function renderPage(title: string, content: string): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} - SEKAI Pass</title>
  <link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96" />
  <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  <link rel="shortcut icon" href="/favicon.ico" />
  <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
  <meta name="apple-mobile-web-app-title" content="SEKAI Pass" />
  <link rel="manifest" href="/site.webmanifest" />
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=Noto+Sans+SC:wght@300;400;500;700&display=swap" rel="stylesheet">
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>${styles}</style>
  <script>
    // Client-side encryption utilities
    async function encryptPassword(password) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
      const timestamp = Date.now().toString();
      const combined = password + '|' + saltHex + '|' + timestamp;
      const encoder = new TextEncoder();
      const data = encoder.encode(combined);
      return btoa(String.fromCharCode(...data));
    }

    function generateNonce() {
      const array = new Uint8Array(16);
      crypto.getRandomValues(array);
      return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function getFingerprint() {
      const data = [
        navigator.userAgent,
        navigator.language,
        screen.width + 'x' + screen.height,
        new Date().getTimezoneOffset()
      ].join('|');
      let hash = 0;
      for (let i = 0; i < data.length; i++) {
        const char = data.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
      }
      return Math.abs(hash).toString(36);
    }

    async function handleFormSubmit(event) {
      event.preventDefault();
      const form = event.target;
      const passwordInput = form.querySelector('input[name="password"]');
      const originalPassword = passwordInput.value;

      // Check Turnstile token
      const turnstileResponse = form.querySelector('input[name="cf-turnstile-response"]');
      if (!turnstileResponse || !turnstileResponse.value) {
        alert('请完成人机验证');
        return false;
      }

      // Encrypt password
      const encryptedPassword = await encryptPassword(originalPassword);

      // Add hidden fields
      const nonce = generateNonce();
      const fingerprint = getFingerprint();
      const timestamp = Date.now();

      // Create hidden inputs
      const fields = {
        'p': encryptedPassword,
        'nonce': nonce,
        'fp': fingerprint,
        'ts': timestamp
      };

      for (const [key, value] of Object.entries(fields)) {
        let input = form.querySelector('input[name="' + key + '"]');
        if (!input) {
          input = document.createElement('input');
          input.type = 'hidden';
          input.name = key;
          form.appendChild(input);
        }
        input.value = value;
      }

      // Clear original password
      passwordInput.value = '';
      passwordInput.removeAttribute('name');

      // Submit form
      form.submit();
    }
  </script>
</head>
<body>
  <div class="container">
    <div class="logo">
      <img src="/logo.png" alt="SEKAI Pass" width="300" />
    </div>
    ${content}
  </div>
</body>
</html>`;
}

export function loginForm(error?: string, siteKey?: string): string {
  const turnstileSiteKey = siteKey || '1x00000000000000000000AA'; // Default test key
  return renderPage("登录", `
    ${error ? `<div class="error">⚠️ ${error}</div>` : ""}
    <form method="POST" action="/login" onsubmit="handleFormSubmit(event)">
      <div class="form-group">
        <label for="username">用户名</label>
        <input type="text" id="username" name="username" required placeholder="请输入用户名" autocomplete="username">
      </div>
      <div class="form-group">
        <label for="password">密码</label>
        <input type="password" id="password" name="password" required placeholder="请输入密码" autocomplete="current-password">
      </div>
      <div class="form-group" style="display: flex; justify-content: center;">
        <div class="cf-turnstile" data-sitekey="${turnstileSiteKey}" data-theme="dark"></div>
      </div>
      <button type="submit">登录</button>
    </form>
    <div class="link">
      <p>还没有账号？ <a href="/register">立即注册</a></p>
    </div>
  `);
}

export function registerForm(error?: string, siteKey?: string): string {
  const turnstileSiteKey = siteKey || '1x00000000000000000000AA'; // Default test key
  return renderPage("注册", `
    ${error ? `<div class="error">⚠️ ${error}</div>` : ""}
    <form method="POST" action="/register" onsubmit="handleFormSubmit(event)">
      <div class="form-group">
        <label for="username">用户名</label>
        <input type="text" id="username" name="username" required placeholder="设置用户名" autocomplete="username">
      </div>
      <div class="form-group">
        <label for="email">电子邮箱</label>
        <input type="email" id="email" name="email" required placeholder="yourname@example.com" autocomplete="email">
      </div>
      <div class="form-group">
        <label for="password">密码</label>
        <input type="password" id="password" name="password" required placeholder="设置密码" autocomplete="new-password">
      </div>
      <div class="form-group">
        <label for="display_name">昵称（可选）</label>
        <input type="text" id="display_name" name="display_name" placeholder="你想被如何称呼？">
      </div>
      <div class="form-group" style="display: flex; justify-content: center;">
        <div class="cf-turnstile" data-sitekey="${turnstileSiteKey}" data-theme="dark"></div>
      </div>
      <button type="submit">完成注册</button>
    </form>
    <div class="link">
      <p>已有账号？ <a href="/login">直接登录</a></p>
    </div>
  `);
}

export function dashboardPage(user: any): string {
  return renderPage("仪表盘", `
    <div class="user-info">
      <p><strong>用户名</strong> <span>${user.username}</span></p>
      <p><strong>邮箱</strong> <span>${user.email}</span></p>
      ${user.displayName ? `<p><strong>昵称</strong> <span>${user.displayName}</span></p>` : ""}
    </div>
    <form method="POST" action="/logout">
      <button type="submit" style="background: linear-gradient(135deg, #718093 0%, #2f3640 100%); width: auto; min-width: 120px; float: right;">退出登录</button>
      <div style="clear: both;"></div>
    </form>
  `);
}

export function authorizePage(app: any, user: any): string {
  const initial = app.name ? app.name.charAt(0).toUpperCase() : 'A';

  // Parse scopes to display
  const scopes = app.scope ? app.scope.split(/\s+/) : ['profile'];
  const scopeDescriptions: Record<string, string> = {
    'openid': 'OpenID Connect 身份验证',
    'profile': '访问您的基本信息（用户名、显示名称）',
    'email': '访问您的电子邮件地址',
    'applications': '管理您的 OAuth 应用程序',
    'admin': '管理员权限'
  };

  return renderPage("授权访问", `
    <div class="auth-header">
      <div class="app-icon">${initial}</div>
      <h2 class="auth-title">授权 ${app.name} 访问</h2>
      <p class="auth-subtitle">该应用希望通过 SEKAI Pass 登录</p>
      <div class="user-badge">
        <span>当前身份</span>
        <strong>${user.username}</strong>
      </div>
    </div>

    <div class="permission-box">
      <div class="permission-header" style="font-size: 14px; font-weight: 600; margin-bottom: 16px; color: var(--text-main);">请求权限</div>
      ${scopes.map(scope => `
        <div class="permission-item" style="display: flex; gap: 12px; margin-bottom: 12px; align-items: start;">
          <svg class="permission-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink: 0; color: var(--primary-color); margin-top: 2px;"><path d="M20 6L9 17l-5-5"/></svg>
          <div>
            <span class="permission-title" style="display: block; font-weight: 500; margin-bottom: 4px;">${scope}</span>
            <div class="permission-desc" style="font-size: 12px; color: var(--text-muted); line-height: 1.5;">${scopeDescriptions[scope] || '未知权限'}</div>
          </div>
        </div>
      `).join('')}
    </div>

    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="${app.client_id}">
      <input type="hidden" name="redirect_uri" value="${app.redirect_uri}">
      ${app.code_challenge ? `<input type="hidden" name="code_challenge" value="${app.code_challenge}">` : ''}
      ${app.code_challenge_method ? `<input type="hidden" name="code_challenge_method" value="${app.code_challenge_method}">` : ''}
      ${app.state ? `<input type="hidden" name="state" value="${app.state}">` : ''}
      ${app.scope ? `<input type="hidden" name="scope" value="${app.scope}">` : ''}
      ${app.nonce ? `<input type="hidden" name="nonce" value="${app.nonce}">` : ''}

      <div class="authorize-actions">
        <button type="submit" name="action" value="allow">确认授权</button>
        <button type="submit" name="action" value="deny" class="btn-secondary">取消</button>
      </div>
      <div class="privacy-note">
        授权即代表您同意该应用按照其服务条款和隐私政策使用您的信息。
      </div>
    </form>
  `);
}
