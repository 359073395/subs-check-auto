const UPSTREAM_BASE =
  'https://raw.githubusercontent.com/359073395/subs-check-auto/main/subs';

const ROUTES = {
  '/mihomo.yaml': {
    file: 'mihomo.yaml',
    contentType: 'text/yaml; charset=utf-8',
  },
  '/base64.txt': {
    file: 'base64.txt',
    contentType: 'text/plain; charset=utf-8',
  },
  '/all.yaml': {
    file: 'all.yaml',
    contentType: 'text/yaml; charset=utf-8',
  },
  '/status': {
    file: 'STATUS.md',
    contentType: 'text/markdown; charset=utf-8',
  },
};

function renderHomePage(origin) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>精选 Top 20 公益节点订阅</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 32px 16px; display: flex; justify-content: center; }
    .card { width: 100%; max-width: 680px; background: #1e293b; border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 24px; box-shadow: 0 20px 50px rgba(0,0,0,0.4); }
    h1 { font-size: 20px; margin: 0 0 8px; }
    p.sub { color: #94a3b8; font-size: 14px; margin: 0 0 20px; }
    .item { background: #0f172a; border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 14px; margin-bottom: 12px; }
    .label { font-size: 14px; font-weight: 600; margin-bottom: 6px; color: #e2e8f0; }
    .row { display: flex; gap: 8px; align-items: center; }
    input { flex: 1; background: transparent; border: none; color: #38bdf8; font-size: 13px; outline: none; font-family: monospace; }
    button { background: #f97316; color: #fff; border: none; border-radius: 8px; padding: 6px 12px; font-size: 13px; font-weight: 600; cursor: pointer; }
    button:hover { background: #ea580c; }
    a { color: #38bdf8; text-decoration: none; font-size: 13px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🚀 精选 Top 20 公益节点订阅</h1>
    <p class="sub">本机复测通过后更新 · 请查看最近检测时间 · 加速订阅文件下载</p>

    <div class="item">
      <div class="label">Clash Verge / Mihomo / FlClash（基础分流配置）</div>
      <div class="row">
        <input id="u1" readonly value="${origin}/mihomo.yaml" />
        <button onclick="copyUrl('u1', this)">复制</button>
      </div>
    </div>

    <div class="item">
      <div class="label">v2rayN / Shadowrocket / Nekobox（Base64 通用订阅）</div>
      <div class="row">
        <input id="u2" readonly value="${origin}/base64.txt" />
        <button onclick="copyUrl('u2', this)">复制</button>
      </div>
    </div>

    <div class="item">
      <div class="label">纯节点列表（YAML）</div>
      <div class="row">
        <input id="u3" readonly value="${origin}/all.yaml" />
        <button onclick="copyUrl('u3', this)">复制</button>
      </div>
    </div>

    <a href="/status" target="_blank">📊 查看最近一次测速与节点清单</a>
  </div>
  <script>
    function copyUrl(id, btn) {
      const el = document.getElementById(id);
      navigator.clipboard.writeText(el.value).then(() => {
        const old = btn.textContent;
        btn.textContent = '已复制';
        setTimeout(() => btn.textContent = old, 1500);
      });
    }
  </script>
</body>
</html>`;
  return new Response(html, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    if (path === '/' || path === '') {
      return renderHomePage(url.origin);
    }

    const route = ROUTES[path];
    if (!route) {
      return new Response('Not Found', { status: 404 });
    }

    const targetUrl = `${UPSTREAM_BASE}/${route.file}`;
    const upstreamResp = await fetch(targetUrl, {
      cf: { cacheTtl: 60, cacheEverything: true },
      headers: {
        'User-Agent': 'Cloudflare-Worker-Subs-Proxy',
      },
    });

    if (!upstreamResp.ok) {
      return new Response(`Upstream Error: ${upstreamResp.status}`, {
        status: 502,
      });
    }

    const headers = new Headers();
    headers.set('content-type', route.contentType);
    headers.set('cache-control', 'public, max-age=60');
    headers.set('access-control-allow-origin', '*');

    return new Response(request.method === 'HEAD' ? null : upstreamResp.body, {
      status: 200,
      headers,
    });
  },
};
