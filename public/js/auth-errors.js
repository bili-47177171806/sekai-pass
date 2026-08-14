// SPDX-License-Identifier: Apache-2.0

/**
 * 认证/表单错误目录 —— 把 SEKAI Pass 前端**真实会收到**的错误，翻译成
 * 「错误码 + 标题 + 说明 + 解决方案」的结构化描述。
 *
 * ── 现状与权衡 ─────────────────────────────────────────────────────
 *
 * 服务端（src/lib/api.ts）返回的是**中文字符串**（`{ error: "用户名或密码错误" }`），
 * 并没有稳定的机器可读错误码。APIClient（utils.js）把它包成 `{ status, message }`
 * 抛出。所以这里只能按**已知中文串的关键词**去匹配——这是字符串耦合，服务端
 * 改文案就可能漏配。为此：
 *   1. 用关键词子串匹配（而非全等），对小改动更鲁棒；
 *   2. 认不出来时按 HTTP status 兜底（5xx=服务器错误、429=频率限制…）；
 *   3. 最终兜底仍原样显示 message，绝不白屏、绝不吞原文。
 *
 * 服务端若将来改为返回稳定 error code，应改成按 code 匹配，这个文件是唯一改动点。
 *
 * 入参可以是 APIClient 抛出的 `{ status, message }`，也可以是一个裸字符串
 * （如 URL 上的 external_error）。
 */

/**
 * @typedef {Object} ErrorDescriptor
 * @property {string} code
 * @property {string} title
 * @property {string} description
 * @property {string} solution
 * @property {string} originalMessage
 */

/**
 * 关键词规则表：message 命中 `match` 里**任一**子串即采用该描述。
 * 顺序从具体到宽泛，先命中先返回。
 * @type {Array<{ match: string[], code: string, title: string, description: string, solution: string }>}
 */
const RULES = [
  // ── 人机验证 ──
  {
    match: ['IP 不匹配'],
    code: 'ERR_CAPTCHA_IP',
    title: '人机验证环境已变化',
    description: '发起验证与提交时的网络地址不一致，验证会话已失效。常见于中途切换了网络或代理。',
    solution: '请刷新页面重新完成人机验证后再提交。',
  },
  {
    match: ['验证会话已使用'],
    code: 'ERR_CAPTCHA_USED',
    title: '人机验证已被使用',
    description: '这次人机验证凭据已经用过一次，出于防重放不能再次使用。',
    solution: '请刷新页面重新完成人机验证。',
  },
  {
    match: ['验证会话无效', '验证会话已过期'],
    code: 'ERR_CAPTCHA_EXPIRED',
    title: '人机验证已过期',
    description: '人机验证会话已失效或超时（有效期约 5 分钟）。',
    solution: '请刷新页面重新完成人机验证后立即提交。',
  },
  {
    match: ['验证方式', '未授权的验证方式'],
    code: 'ERR_CAPTCHA_METHOD',
    title: '人机验证方式不匹配',
    description: '本次提交使用的人机验证方式与当前操作要求的不一致。',
    solution: '请刷新页面，用页面上提供的验证方式重新验证后提交。',
  },
  {
    match: ['验证数据不完整'],
    code: 'ERR_CAPTCHA_INCOMPLETE',
    title: '人机验证数据不完整',
    description: '提交的人机验证数据缺失，无法完成校验。',
    solution: '请刷新页面重新完成人机验证。',
  },
  {
    match: ['人机验证失败'],
    code: 'ERR_CAPTCHA_FAILED',
    title: '人机验证未通过',
    description: '人机验证校验失败，可能是勾选超时或验证服务临时异常。',
    solution: '请刷新页面重新完成验证；若反复失败，请稍后再试或更换网络。',
  },
  {
    match: ['进行中', '还在进行'],
    code: 'ERR_CAPTCHA_PENDING',
    title: '人机验证进行中',
    description: '人机验证尚未完成，请等待其结束。',
    solution: '请稍候片刻，待验证完成后再点击提交。',
  },
  {
    match: ['完成人机验证', '完成上方的人机验证', '完成验证'],
    code: 'ERR_CAPTCHA_REQUIRED',
    title: '请先完成人机验证',
    description: '提交前需要先通过页面上的人机验证。',
    solution: '请完成页面上的人机验证后再提交。',
  },
  // ── 登录 ──
  {
    match: ['用户名或密码错误'],
    code: 'ERR_LOGIN_BAD_CREDENTIALS',
    title: '用户名或密码错误',
    description: '输入的用户名或密码与账号不符。出于安全考虑，系统不会告知具体是哪一项错误。',
    solution: '请检查用户名与密码后重试；忘记密码可尝试使用已绑定的第三方账号登录。',
  },
  {
    match: ['用户名和密码不能为空'],
    code: 'ERR_LOGIN_EMPTY',
    title: '用户名和密码不能为空',
    description: '登录需要同时填写用户名和密码。',
    solution: '请填写完整后再提交。',
  },
  {
    match: ['未启用密码登录'],
    code: 'ERR_LOGIN_NO_PASSWORD',
    title: '该账号未启用密码登录',
    description: '这个账号是通过第三方账号创建的，尚未设置可用于登录的密码。',
    solution: '请改用已绑定的第三方账号登录。',
  },
  // ── 注册 ──
  {
    match: ['用户名或邮箱已被使用'],
    code: 'ERR_REGISTER_TAKEN',
    title: '用户名或邮箱已被使用',
    description: '该用户名或邮箱已被其他账号占用。',
    solution: '请更换用户名或邮箱后重试；若这是你本人的账号，请直接登录。',
  },
  {
    match: ['必填项'],
    code: 'ERR_REGISTER_EMPTY',
    title: '必填项未填写完整',
    description: '注册所需的必填字段有缺失。',
    solution: '请把所有必填项填写完整后再提交。',
  },
  {
    match: ['密码长度'],
    code: 'ERR_WEAK_PASSWORD',
    title: '密码强度不足',
    description: '密码长度不满足最低要求（至少 8 个字符）。',
    solution: '请设置一个至少 8 位的密码后重试。',
  },
  // ── 请求 / 票据 / 授权 ──
  {
    match: ['请求参数无效', 'Invalid request parameters'],
    code: 'ERR_BAD_REQUEST',
    title: '请求参数无效',
    description: '提交的请求参数不合法，可能是页面停留过久或链接被篡改。',
    solution: '请刷新页面后重新操作，不要手动改动地址栏参数。',
  },
  {
    match: ['票据'],
    code: 'ERR_EXTERNAL_TICKET',
    title: '登录票据无效或已失效',
    description: '第三方登录的一次性票据无效、已过期或已被使用。',
    solution: '请返回登录页重新发起第三方登录。',
  },
  {
    match: ['保留至少一种登录方式'],
    code: 'ERR_LAST_LOGIN_METHOD',
    title: '需要保留至少一种登录方式',
    description: '这是你账号上最后一种可用的登录方式，删除后将无法登录，因此被拒绝。',
    solution: '请先绑定另一种登录方式，再删除当前这一种。',
  },
  {
    match: ['通行密钥'],
    code: 'ERR_PASSKEY_FAILED',
    title: '通行密钥登录失败',
    description: '使用通行密钥（Passkey）登录未能完成，可能是取消了系统弹窗或设备不支持。',
    solution: '请重试通行密钥登录，或改用用户名密码 / 第三方账号登录。',
  },
  {
    match: ['第三方登录', '无法启动第三方'],
    code: 'ERR_EXTERNAL_START',
    title: '无法启动第三方登录',
    description: '发起第三方登录失败，可能是该登录方式暂不可用或网络异常。',
    solution: '请稍后重试，或改用其它登录方式。',
  },
  {
    match: ['授权失败'],
    code: 'ERR_AUTHORIZE_FAILED',
    title: '授权失败',
    description: '向应用授权时发生错误，未能签发授权码。',
    solution: '请刷新页面重试；若持续出现，请稍后再试。',
  },
  {
    match: ['加载应用信息失败'],
    code: 'ERR_APP_INFO',
    title: '加载应用信息失败',
    description: '无法获取本次授权请求对应的应用信息，可能是链接有误或应用不存在。',
    solution: '请确认授权链接来自可信来源；若问题持续，请联系该应用的开发者。',
  },
];

/** 按 HTTP status 的兜底描述（关键词都没命中时用）。 */
function fromStatus(status, message) {
  if (status === 401) {
    return {
      code: 'ERR_SESSION_EXPIRED',
      title: '登录状态已失效',
      description: '当前会话已过期或未登录。',
      solution: '请重新登录后再操作。',
    };
  }
  if (status === 429) {
    return {
      code: 'ERR_RATE_LIMIT',
      title: '操作过于频繁',
      description: '短时间内请求次数过多，已被暂时限制。',
      solution: '请稍等片刻后再试。',
    };
  }
  if (typeof status === 'number' && status >= 500) {
    return {
      code: 'ERR_SERVER',
      title: '服务器出错了',
      description: '服务端处理请求时发生错误，这不是你的操作导致的。',
      solution: '请稍后重试；若持续出现，请联系站点维护者。',
    };
  }
  return {
    code: 'ERR_REQUEST_FAILED',
    title: '操作失败',
    description: message ? '请求未能完成。' : '请求未能完成，且没有更多信息。',
    solution: '请刷新页面重试；若持续出现，请把下方的错误信息反馈给站点维护者。',
  };
}

/**
 * 把任意前端错误翻译成结构化描述。
 *
 * @param {unknown} error `{ status, message }`（APIClient 抛出）或裸字符串
 * @returns {ErrorDescriptor}
 */
export function describeError(error) {
  let message = '';
  let status;

  if (typeof error === 'string') {
    message = error;
  } else if (error && typeof error === 'object') {
    message = error.message != null ? String(error.message) : '';
    if (typeof error.status === 'number') status = error.status;
  }

  let base = null;
  for (const rule of RULES) {
    if (rule.match.some((kw) => message.indexOf(kw) !== -1)) {
      base = rule;
      break;
    }
  }
  if (!base) base = fromStatus(status, message);

  return {
    code: base.code,
    title: base.title,
    description: base.description,
    solution: base.solution,
    originalMessage: message,
  };
}

export default describeError;
