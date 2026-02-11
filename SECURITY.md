# 安全政策 (Security Policy)

## 🔒 支持的版本

我们为以下版本提供安全更新：

| 版本 | 支持状态 |
| --- | --- |
| 最新版本 | ✅ 支持 |
| 旧版本 | ❌ 不支持 |

我们建议始终使用最新版本以获得最佳安全性。

## 🐛 报告漏洞

如果你发现了安全漏洞，**请不要公开披露**。我们非常重视安全问题，并会尽快处理。

### 报告方式

**推荐方式：GitHub Security Advisories**

1. 访问项目的 Security 标签
2. 点击 "Report a vulnerability"
3. 填写漏洞详情
4. 提交报告

**备用方式：私密 Issue**

如果无法使用 Security Advisories，可以：
1. 创建一个 Issue
2. 标题使用 `[SECURITY]` 前缀
3. 在描述中说明这是安全问题
4. 我们会尽快将其转为私密讨论

### 报告内容

请在报告中包含以下信息：

- **漏洞类型**：XSS、SQL 注入、CSRF、认证绕过等
- **影响范围**：哪些功能/组件受影响
- **复现步骤**：详细的步骤说明
- **影响评估**：可能造成的危害
- **修复建议**：如果有的话
- **环境信息**：浏览器、操作系统等

### 示例报告

```markdown
## 漏洞类型
OAuth 2.1 授权码重放攻击

## 影响范围
OAuth 授权流程

## 复现步骤
1. 获取授权码
2. 使用授权码交换访问令牌
3. 再次使用相同授权码尝试交换令牌

## 影响评估
攻击者可能获取未授权的访问令牌

## 修复建议
确保授权码单次使用后立即失效
```

## ⏱️ 响应时间

- **初步响应**：48 小时内
- **漏洞确认**：7 天内
- **修复发布**：根据严重程度，14-30 天内

## 🎖️ 致谢

我们会在修复发布后公开致谢报告者（除非你要求匿名）。

感谢以下安全研究人员的贡献：
- （待添加）

## 🔐 安全最佳实践

### 对于用户

1. **保持更新**：使用最新版本
2. **强密码**：使用复杂且唯一的密码
3. **HTTPS**：确保使用 HTTPS 访问
4. **警惕钓鱼**：不要点击可疑链接

### 对于开发者

1. **输入验证**：验证所有用户输入
2. **输出转义**：转义所有输出到 HTML 的内容
3. **认证授权**：正确实现认证和授权
4. **依赖更新**：定期更新依赖包
5. **代码审查**：所有代码都需要审查

### 对于部署者（SEKAI Pass 特定）

#### 环境配置

- ✅ 使用强随机密钥作为 `KEY_ENCRYPTION_SECRET`
- ✅ 定期轮换密钥和令牌
- ✅ 在生产环境中强制使用 HTTPS
- ✅ 正确配置 CORS 和 CSP 头部

#### 数据库安全

- ✅ 定期备份 D1 数据库
- ✅ 限制数据库访问权限
- ✅ 监控异常查询活动

#### 密钥管理

- ✅ 不要在代码中硬编码密钥
- ✅ 使用 Cloudflare Secrets 存储敏感信息
- ✅ 不要将 `wrangler.toml` 或 `.dev.vars` 提交到公共仓库

#### OAuth/OIDC 安全

- ✅ 验证所有 redirect_uri
- ✅ 强制使用 PKCE（已默认启用）
- ✅ 使用短期访问令牌（1 小时）
- ✅ 实施令牌轮换机制（已默认启用）
- ✅ 验证 state 参数防止 CSRF

#### 监控和日志

- ✅ 启用 Cloudflare Workers 日志
- ✅ 监控异常登录尝试
- ✅ 设置告警机制

## 🛡️ 安全功能

本项目实施的安全措施：

### 通用安全

- ✅ HTTPS 强制（生产环境）
- ✅ CORS 配置
- ✅ 输入验证
- ✅ XSS 防护
- ✅ CSRF 防护

### SEKAI Pass 特定安全

- ✅ PBKDF2 密码哈希（100,000 次迭代，SHA-256）
- ✅ 强制 PKCE（OAuth 2.1 合规）
- ✅ 短期访问令牌（1 小时）
- ✅ 刷新令牌轮换
- ✅ 授权码单次使用
- ✅ State 参数 CSRF 防护
- ✅ ID Token 签名（ES256）
- ✅ 安全 Cookie（SameSite=Lax）
- ✅ 生产环境强制 HTTPS

## 📚 相关资源

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Security Cheat Sheet](https://cheatsheetseries.owasp.org/)
- [Cloudflare Security](https://www.cloudflare.com/learning/security/)
- [OAuth 2.1 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

## 📧 联系方式

如有其他安全相关问题，可以通过以下方式联系：

- GitHub Issues（非敏感问题）
- Security Advisories（敏感问题）

---

感谢你帮助我们保持项目的安全！🙏

<div align="center">

**安全是我们的首要任务**

Made with 💜 by the [25-ji-code-de](https://github.com/25-ji-code-de) team

</div>
