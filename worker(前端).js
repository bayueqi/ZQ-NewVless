import { connect } from 'cloudflare:sockets';

export default {
	async fetch(req, env) {
		const getUserConfig = async () => {
			try {
				const config = await env.NewVless?.get('user_config', 'json');
				const merged = config || { uuid: 'ef9d104e-ca0e-4202-ba4b-a0afb969c747', domain: '', port: '443', s5: '', proxyIp: '', domains: [], ports: [] };
				if (!Array.isArray(merged.domains)) merged.domains = [];
				if (!Array.isArray(merged.ports)) merged.ports = [];
				const d = (merged.domain || '').trim();
				if (d && !merged.domains.includes(d)) merged.domains.push(d);
				const pNum = Math.max(1, Math.min(65535, parseInt(merged.port || '443', 10) || 443));
				if (!merged.ports.some(x => +x === pNum)) merged.ports.push(pNum);
				return merged;
			} catch {
				return { uuid: 'ef9d104e-ca0e-4202-ba4b-a0afb969c747', domain: '', port: '443', s5: '', proxyIp: '', domains: [], ports: [443] };
			}
		};

		const buildVlessUri = (rawPathQuery, uuid, label, workerHost, preferredDomain, port, s5, proxyIp) => {
			let path = rawPathQuery;
			if (!path) {
				const params = ['mode=auto', 'direct'];
				if (s5) params.push('s5=' + encodeURIComponent(s5));
				if (proxyIp) params.push('proxyip=' + encodeURIComponent(proxyIp));
				path = s5 || proxyIp ? '/?' + params.join('&') : '/?mode=direct';
			}
			return `vless://${uuid}@${preferredDomain}:${port}?encryption=none&security=tls&sni=${workerHost}&type=ws&host=${workerHost}&path=${encodeURIComponent(path)}#${encodeURIComponent(label || preferredDomain)}`;
		};

		const buildVariants = (s5, proxyIp) => {
			const v = [{ label: '仅直连', raw: '/?mode=direct' }];
			if (s5) v.push({ label: '仅SOCKS5', raw: `/?mode=s5&s5=${s5}` }, { label: '直连优先，回退SOCKS5', raw: `/?mode=auto&direct&s5=${s5}` }, { label: 'SOCKS5优先，回退直连', raw: `/?mode=auto&s5=${s5}&direct` });
			if (proxyIp) v.push({ label: '直连优先，回退ProxyIP', raw: `/?mode=auto&direct&proxyip=${proxyIp}` }, { label: 'ProxyIP优先，回退直连', raw: `/?mode=auto&proxyip=${proxyIp}&direct` });
			if (s5 && proxyIp) v.push({ label: 'SOCKS5优先，回退ProxyIP', raw: `/?mode=auto&s5=${s5}&proxyip=${proxyIp}` }, { label: 'ProxyIP优先，回退SOCKS5', raw: `/?mode=auto&proxyip=${proxyIp}&s5=${s5}` }, { label: '直连→SOCKS5→ProxyIP', raw: `/?mode=auto&direct&s5=${s5}&proxyip=${proxyIp}` }, { label: '直连→ProxyIP→SOCKS5', raw: `/?mode=auto&direct&proxyip=${proxyIp}&s5=${s5}` }, { label: 'SOCKS5→直连→ProxyIP', raw: `/?mode=auto&s5=${s5}&direct&proxyip=${proxyIp}` }, { label: 'SOCKS5→ProxyIP→直连', raw: `/?mode=auto&s5=${s5}&proxyip=${proxyIp}&direct` }, { label: 'ProxyIP→直连→SOCKS5', raw: `/?mode=auto&proxyip=${proxyIp}&direct&s5=${s5}` }, { label: 'ProxyIP→SOCKS5→直连', raw: `/?mode=auto&proxyip=${proxyIp}&s5=${s5}&direct` });
			return v;
		};

		const getDomainPortLists = (request, cfg) => {
			const workerHost = new URL(request.url).hostname;
			const domains = [...new Set((cfg.domains || []).map(x => (x || '').trim()).filter(Boolean))];
			if (!domains.length) domains.push((cfg.domain || workerHost).trim() || workerHost);
			const ports = [...new Set((cfg.ports || []).concat(cfg.port || []).map(p => Math.max(1, Math.min(65535, +p || 443))))];
			if (!ports.length) ports.push(443);
			return { workerHost, domains, ports };
		};

		const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json; charset=utf-8' } });

		if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
			const [client, ws] = Object.values(new WebSocketPair());
			ws.accept();
			const userConfig = await getUserConfig();

			const u = new URL(req.url);

			if (u.pathname.includes('%3F')) {
				const decoded = decodeURIComponent(u.pathname);
				const queryIndex = decoded.indexOf('?');
				if (queryIndex !== -1) {
					u.search = decoded.substring(queryIndex);
					u.pathname = decoded.substring(0, queryIndex);
				}
			}

			const mode = u.searchParams.get('mode') || 'auto';
			const s5Param = u.searchParams.get('s5');
			const proxyParam = u.searchParams.get('proxyip');
			const path = s5Param ? s5Param : u.pathname.slice(1);

			const socks5 = path.includes('@') ? (() => {
				const [cred, server] = path.split('@');
				const [user, pass] = cred.split(':');
				const [host, port = 443] = server.split(':');
				return { user, pass, host, port: +port };
			})() : null;
			const PROXY_IP = proxyParam ? String(proxyParam) : null;

			const getOrder = () => {
				if (mode === 'proxy') return ['direct', 'proxy'];
				if (mode !== 'auto') return [mode];
				const order = [];
				const searchStr = u.search.slice(1);
				for (const pair of searchStr.split('&')) {
					const key = pair.split('=')[0];
					if (key === 'direct') order.push('direct');
					else if (key === 's5') order.push('s5');
					else if (key === 'proxyip') order.push('proxy');
				}
				return order.length ? order : ['direct'];
			};

			let remote = null, udpWriter = null, isDNS = false;
			const socks5Connect = async (targetHost, targetPort) => {
				const sock = connect({ hostname: socks5.host, port: socks5.port });
				await sock.opened;
				const w = sock.writable.getWriter(), r = sock.readable.getReader();
				await w.write(new Uint8Array([5, 2, 0, 2]));
				const auth = (await r.read()).value;
				if (auth[1] === 2 && socks5.user) {
					const u = new TextEncoder().encode(socks5.user), p = new TextEncoder().encode(socks5.pass);
					await w.write(new Uint8Array([1, u.length, ...u, p.length, ...p]));
					await r.read();
				}
				const d = new TextEncoder().encode(targetHost);
				await w.write(new Uint8Array([5, 1, 0, 3, d.length, ...d, targetPort >> 8, targetPort & 0xff]));
				await r.read();
				w.releaseLock(); r.releaseLock();
				return sock;
			};

			new ReadableStream({
				start(ctrl) {
					ws.addEventListener('message', e => ctrl.enqueue(e.data));
					ws.addEventListener('close', () => {
						remote?.close();
						ctrl.close();
					});
					ws.addEventListener('error', () => {
						remote?.close();
						ctrl.error();
					});

					const early = req.headers.get('sec-websocket-protocol');
					if (early) {
						try {
							ctrl.enqueue(Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')),
								c => c.charCodeAt(0)).buffer);
						} catch {}
					}
				}
			}).pipeTo(new WritableStream({
				async write(data) {
					if (isDNS) return udpWriter?.write(data);
					if (remote) {
						const w = remote.writable.getWriter();
						await w.write(data);
						w.releaseLock();
						return;
					}

					if (data.byteLength < 24) return;
					const uuidBytes = new Uint8Array(data.slice(1, 17));
					const expectedUUID = userConfig.uuid.replace(/-/g, '');
					for (let i = 0; i < 16; i++) {
						if (uuidBytes[i] !== parseInt(expectedUUID.substr(i * 2, 2), 16)) return;
					}

					const view = new DataView(data);
					const optLen = view.getUint8(17);
					const cmd = view.getUint8(18 + optLen);
					if (cmd !== 1 && cmd !== 2) return;

					let pos = 19 + optLen;
					const port = view.getUint16(pos);
					const type = view.getUint8(pos + 2);
					pos += 3;

					let addr = '';
					if (type === 1) {
						addr =
							`${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
						pos += 4;
					} else if (type === 2) {
						const len = view.getUint8(pos++);
						addr = new TextDecoder().decode(data.slice(pos, pos + len));
						pos += len;
					} else if (type === 3) {
						const ipv6 = [];
						for (let i = 0; i < 8; i++, pos += 2) ipv6.push(view.getUint16(pos)
							.toString(16));
						addr = ipv6.join(':');
					} else return;

					const header = new Uint8Array([data[0], 0]);
					const payload = data.slice(pos);
					if (cmd === 2) {
						if (port !== 53) return;
						isDNS = true;
						let sent = false;
						const {
							readable,
							writable
						} = new TransformStream({
							transform(chunk, ctrl) {
								for (let i = 0; i < chunk.byteLength;) {
									const len = new DataView(chunk.slice(i, i + 2))
										.getUint16(0);
									ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
									i += 2 + len;
								}
							}
						});

						readable.pipeTo(new WritableStream({
							async write(query) {
								try {
									const resp = await fetch(
										'https://1.1.1.1/dns-query', {
											method: 'POST',
											headers: {
												'content-type': 'application/dns-message'
											},
											body: query
										});
									if (ws.readyState === 1) {
										const result = new Uint8Array(await resp
											.arrayBuffer());
										ws.send(new Uint8Array([...(sent ? [] :
												header), result
											.length >> 8, result
											.length & 0xff, ...result
										]));
										sent = true;
									}
								} catch {}
							}
						}));
						udpWriter = writable.getWriter();
						return udpWriter.write(payload);
					}
					let sock = null;
					for (const method of getOrder()) {
						try {
							if (method === 'direct') {
								sock = connect({ hostname: addr, port });
								await sock.opened;
								break;
							} else if (method === 's5' && socks5) {
								sock = await socks5Connect(addr, port);
								break;
							} else if (method === 'proxy' && PROXY_IP) {
								const [ph, pp = port] = PROXY_IP.split(':');
								sock = connect({ hostname: ph, port: +pp || port });
								await sock.opened;
								break;
							}
						} catch {}
					}

					if (!sock) return;

					remote = sock;
					const w = sock.writable.getWriter();
					await w.write(payload);
					w.releaseLock();

					let sent = false;
					sock.readable.pipeTo(new WritableStream({
						write(chunk) {
							if (ws.readyState === 1) {
								ws.send(sent ? chunk : new Uint8Array([...header, ...
									new Uint8Array(chunk)
								]));
								sent = true;
							}
						},
						close: () => ws.readyState === 1 && ws.close(),
						abort: () => ws.readyState === 1 && ws.close()
					})).catch(() => {});
				}
			})).catch(() => {});

			return new Response(null, {
				status: 101,
				webSocket: client
			});
		}

		const url = new URL(req.url);


		if (url.pathname.startsWith('/api/config/')) {
			const pathParts = url.pathname.split('/').filter(p => p);
			const urlUUID = pathParts[2];
			if (!urlUUID) {
				return json({ error: 'UUID不能为空' }, 400);
			}
			const userConfig = await getUserConfig();
			if (req.method === 'GET') {
				if (urlUUID !== userConfig.uuid) {
					return json({ error: 'UUID错误，无权访问' }, 403);
				}
				const { fallbackTimeout, ...configWithoutTimeout } = userConfig;
				return json(configWithoutTimeout);
			} else if (req.method === 'POST') {
				try {
					const incoming = await req.json();
					if (!incoming.uuid || typeof incoming.uuid !== 'string') {
						return json({ error: 'UUID不能为空' }, 400);
					}
					if (urlUUID !== userConfig.uuid && urlUUID !== incoming.uuid) {
						return json({ error: 'UUID错误，无权访问' }, 403);
					}
					let domains = [];
					if (Array.isArray(incoming.domains)) domains = incoming.domains.map(x => (x || '').trim()).filter(Boolean);
					if (incoming.domain) { const d = (incoming.domain + '').trim(); if (d && !domains.includes(d)) domains.unshift(d); }
					let ports = [];
					if (Array.isArray(incoming.ports)) ports = incoming.ports.map(x => Math.max(1, Math.min(65535, parseInt((x + ''), 10) || 443)));
					if (incoming.port) { const pn = Math.max(1, Math.min(65535, parseInt((incoming.port + ''), 10) || 443)); if (!ports.includes(pn)) ports.unshift(pn); }
					domains = Array.from(new Set(domains));
					ports = Array.from(new Set(ports));
					if (domains.length === 0) domains.push('');
					if (ports.length === 0) ports.push(443);
					const normalized = { uuid: incoming.uuid, domain: (domains[0] || ''), port: String(ports[0] || 443), s5: incoming.s5 || '', proxyIp: incoming.proxyIp || '', domains: domains.filter(Boolean), ports };
					if (env.NewVless) await env.NewVless.put('user_config', JSON.stringify(normalized));
					return json({ success: true, message: '配置保存成功' });
				} catch (error) {
					return json({ error: '配置保存失败' }, 500);
				}
			}
		}

		if (url.pathname === '/api/probe') {
			const params = url.searchParams, inputUUID = params.get('uuid');
			if (!inputUUID) return json({ ok: false, message: '缺少 UUID 参数' }, 400);
			const userConfig = await getUserConfig();
			if (inputUUID !== userConfig.uuid) return json({ ok: false, message: 'UUID 错误，无权访问' }, 403);
			const type = params.get('type'), timeoutMs = Math.max(50, Math.min(20000, +(params.get('timeout') || 0) || 1000)), started = Date.now();
			try {
				if (type === 'proxyip') {
					const [host, port = 443] = (params.get('proxyip') || userConfig.proxyIp || '').split(':');
					if (!host) return json({ ok: false, ms: 0, message: '未填写 ProxyIP' }, 400);
					const sock = connect({ hostname: host, port: +port });
					const res = await Promise.race([sock.opened.then(() => 'ok'), new Promise(r => setTimeout(() => r('timeout'), timeoutMs))]);
					try { sock.close(); } catch {}
					return json({ ok: res === 'ok', ms: Date.now() - started, message: res === 'ok' ? '可用' : '连接超时' }, res === 'ok' ? 200 : 408);
				}
				if (type === 's5') {
					const raw = params.get('s5') || userConfig.s5 || '';
					if (!raw) return json({ ok: false, ms: 0, message: '未填写 SOCKS5' }, 400);
					const [auth, server] = raw.includes('@') ? raw.split('@') : ['', raw];
					const [user, pass] = auth.split(':'), [host, port = 443] = server.split(':');
					const sock = connect({ hostname: host, port: +port });
					await Promise.race([sock.opened, new Promise(r => setTimeout(() => r('timeout'), timeoutMs))]);
					const w = sock.writable.getWriter(), r = sock.readable.getReader();
					await w.write(new Uint8Array([5, 2, 0, 2]));
					const authRes = await Promise.race([r.read(), new Promise(r2 => setTimeout(() => r2({ timeout: true }), timeoutMs))]);
					if (!authRes || authRes.timeout || !authRes.value) { try { r.releaseLock(); w.releaseLock(); sock.close(); } catch {} return json({ ok: false, ms: Date.now() - started, message: '握手超时' }, 408); }
					if (authRes.value[1] === 2 && user) {
						const u = new TextEncoder().encode(user), p = new TextEncoder().encode(pass);
						await w.write(new Uint8Array([1, u.length, ...u, p.length, ...p]));
						await r.read();
					}
					const d = new TextEncoder().encode('example.com');
					await w.write(new Uint8Array([5, 1, 0, 3, d.length, ...d, 443 >> 8, 443 & 0xff]));
					const connRes = await Promise.race([r.read(), new Promise(r2 => setTimeout(() => r2({ timeout: true }), timeoutMs))]);
					try { r.releaseLock(); w.releaseLock(); sock.close(); } catch {}
					return json({ ok: connRes && !connRes.timeout && connRes.value, ms: Date.now() - started, message: connRes && !connRes.timeout && connRes.value ? '可用' : 'CONNECT 超时' }, connRes && !connRes.timeout && connRes.value ? 200 : 408);
				}
				return json({ ok: false, ms: 0, message: 'type 参数无效' }, 400);
			} catch (e) {
				return json({ ok: false, ms: Date.now() - started, message: '探测失败' }, 500);
			}
		}

		if (url.pathname.startsWith('/sub')) {
			const parts = url.pathname.split('/').filter(p => p);
			const inputUUID = url.searchParams.get('uuid') || parts[1];
			if (!inputUUID) return new Response('missing uuid', { status: 400 });
			const userConfig = await getUserConfig();
			if (inputUUID !== userConfig.uuid) return new Response('Not Found', { status: 404 });
			const { workerHost, domains, ports } = getDomainPortLists(req, userConfig);
			const variants = buildVariants(userConfig.s5, userConfig.proxyIp);
			const ua = (req.headers.get('User-Agent') || '').toLowerCase();
			const isSubConverterRequest = url.searchParams.has('b64') || url.searchParams.has('base64') || req.headers.get('subconverter-request') || req.headers.get('subconverter-version') || ua.includes('subconverter');
			const 订阅类型 = isSubConverterRequest
				? 'mixed'
				: url.searchParams.has('target')
					? url.searchParams.get('target')
					: url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo')
						? 'clash'
						: url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') || ua.includes('sing-box')
							? 'singbox'
							: url.searchParams.has('surge') || ua.includes('surge')
								? 'surge&ver=4'
								: url.searchParams.has('quanx') || ua.includes('quantumult')
									? 'quanx'
									: url.searchParams.has('loon') || ua.includes('loon')
										? 'loon'
										: 'mixed';
			const out = [];
			for (const d of domains) {
				for (const p of ports) {
					for (const v of variants) out.push(buildVlessUri(v.raw, userConfig.uuid, `${v.label} ${d}:${p}`, workerHost, d, p, userConfig.s5, userConfig.proxyIp));
				}
			}
			const nodesContent = out.join('\n');
			const responseHeaders = {
				"content-type": "text/plain; charset=utf-8",
				"Profile-Update-Interval": "3",
				"Profile-web-page-url": new URL(req.url).origin + '/' + userConfig.uuid,
				"Cache-Control": "no-store",
				"Content-Disposition": "attachment; filename=newvless"
			};
			
			// 处理不同类型的订阅
			if (订阅类型 === 'mixed') {
				// 标准格式，Base64编码
				const encoded = btoa(unescape(encodeURIComponent(nodesContent)));
				return new Response(encoded + '\n', { status: 200, headers: responseHeaders });
			} else {
				const encodedNodes = btoa(unescape(encodeURIComponent(nodesContent)));
				const 订阅转换URL = `https://subapi.vpnjacky.dpdns.org/sub?target=${订阅类型}&url=${encodeURIComponent(encodedNodes)}&emoji=false&insert=false`;
				try {
					const response = await fetch(订阅转换URL, { 
						headers: { 
							'User-Agent': 'Subconverter for ' + 订阅类型,
							'Accept': '*/*'
						}
					});
					if (response.ok) {
						const 转换后内容 = await response.text();
						if (订阅类型 === 'clash') {
							responseHeaders["content-type"] = 'application/x-yaml; charset=utf-8';
						} else if (订阅类型 === 'singbox') {
							responseHeaders["content-type"] = 'application/json; charset=utf-8';
						}
						return new Response(转换后内容, { status: 200, headers: responseHeaders });
					} else {
						const errorText = await response.text().catch(() => '');
						return text('订阅转换失败: ' + response.statusText + '\n' + errorText + '\nURL: ' + 订阅转换URL, 500);
					}
				} catch (error) {
					return new Response(encodedNodes + '\n', { status: 200, headers: responseHeaders });
				}
			}
		}

		if (url.pathname === '/' || url.pathname === '/index.html') {
			const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ZQ-NewVless</title><link rel="icon" type="image/png" href="https://img.520jacky.dpdns.org/i/2026/02/13/574881.webp"><style>:root{--primary:#2563eb;--primary-light:#3b82f6;--primary-dark:#1d4ed8;--bg-gradient-start:#eff6ff;--bg-gradient-end:#dbeafe;--card-bg:rgba(255,255,255,0.95);--text-primary:#1e3a5f;--text-secondary:#64748b;--border-color:#bfdbfe;--shadow:0 4px 6px -1px rgba(37,99,235,0.1),0 2px 4px -1px rgba(37,99,235,0.06);--shadow-lg:0 20px 25px -5px rgba(37,99,235,0.15),0 10px 10px -5px rgba(37,99,235,0.1)}*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;margin:0;min-height:100vh;background:linear-gradient(135deg,var(--bg-gradient-start) 0%,var(--bg-gradient-end) 100%);color:var(--text-primary);line-height:1.6;display:flex;align-items:center;justify-content:center}.card{background:var(--card-bg);border-radius:20px;padding:32px;box-shadow:var(--shadow-lg);border:1px solid var(--border-color);max-width:500px;width:90%;backdrop-filter:blur(10px)}h1{margin:0 0 24px;font-size:28px;font-weight:700;text-align:center;background:linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}.form-group{margin-bottom:20px}label{display:block;margin-bottom:8px;font-weight:600;color:var(--text-primary)}input[type="text"]{width:100%;padding:14px;border:2px solid var(--border-color);border-radius:12px;background:rgba(255,255,255,0.8);color:var(--text-primary);font-size:16px;box-sizing:border-box;transition:all .3s ease}input[type="text"]:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(37,99,235,0.1)}button{width:100%;background:linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);color:#fff;border:none;border-radius:12px;padding:14px;font-size:16px;font-weight:600;cursor:pointer;transition:all .3s ease;box-shadow:var(--shadow)}button:hover{background:linear-gradient(135deg,var(--primary-dark) 0%,var(--primary) 100%);transform:translateY(-2px);box-shadow:var(--shadow-lg)}.error{margin-top:16px;color:#dc2626;text-align:center;font-size:14px;padding:12px;border-radius:8px;background:rgba(220,38,38,0.1);border:1px solid rgba(220,38,38,0.2)}</style></head><body><div class="card"><h1>ZQ-NewVless</h1><form method="get"><div class="form-group"><label for="uuid">请输入UUID</label><input type="text" id="uuid" name="uuid" required placeholder="请输入正确的UUID"></div><button type="submit">进入节点界面</button></form><div class="error" id="error" style="display:none">UUID错误，请检查后重新输入</div></div><script>document.querySelector('form').addEventListener('submit',function(e){e.preventDefault();const uuid=document.getElementById('uuid').value.trim();if(!uuid)return;fetch('/' + uuid).then(response=>{if(response.ok){window.location.href='/' + uuid;}else{const errorDiv=document.getElementById('error');errorDiv.style.display='block';errorDiv.textContent='UUID错误，请检查后重新输入';}}).catch(()=>{const errorDiv=document.getElementById('error');errorDiv.style.display='block';errorDiv.textContent='UUID错误，请检查后重新输入';});});</script></body></html>`;
			return new Response(html, {headers:{'content-type':'text/html; charset=utf-8'}});
		}

		// Node interface at /{UUID}
		const pathParts = url.pathname.split('/').filter(p => p);
		if (pathParts.length === 1) {
			const inputUUID = pathParts[0];
			
			// Get user config
			const userConfig = await getUserConfig();
			
			// Check if input UUID matches user config UUID
			if (inputUUID !== userConfig.uuid) {
				return new Response('Not Found', { status: 404 });
			}
			const userUUID = userConfig.uuid;
			const origin = new URL(req.url).origin;
			const subUrl = `${origin}/sub/${userUUID}`;
			
			const lists = getDomainPortLists(req, userConfig);
			const variants = buildVariants(userConfig.s5, userConfig.proxyIp);
			const allNodeUris = [];
			for (const d of lists.domains) {
				for (const p of lists.ports) {
					for (const v of variants) {
						const full = buildVlessUri(v.raw, userUUID, `${v.label} ${d}:${p}`, lists.workerHost, d, p, userConfig.s5, userConfig.proxyIp);
						allNodeUris.push(full);
					}
				}
			}
			const allNodesJson = JSON.stringify(allNodeUris);
			const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ZQ-NewVless</title><link rel="icon" type="image/png" href="https://img.520jacky.dpdns.org/i/2026/02/13/574881.webp"><style>:root{--primary:#2563eb;--primary-light:#3b82f6;--primary-dark:#1d4ed8;--bg-gradient-start:#eff6ff;--bg-gradient-end:#dbeafe;--card-bg:rgba(255,255,255,0.95);--text-primary:#1e3a5f;--text-secondary:#64748b;--border-color:#bfdbfe;--shadow:0 4px 6px -1px rgba(37,99,235,0.1),0 2px 4px -1px rgba(37,99,235,0.06);--shadow-lg:0 20px 25px -5px rgba(37,99,235,0.15),0 10px 10px -5px rgba(37,99,235,0.1)}*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;margin:0;min-height:100vh;background:linear-gradient(135deg,var(--bg-gradient-start) 0%,var(--bg-gradient-end) 100%);color:var(--text-primary);line-height:1.6}.wrap{max-width:1000px;margin:0 auto;padding:32px 24px;position:relative}.header{text-align:center;margin-bottom:32px;padding:24px 0;border-bottom:2px solid var(--border-color)}h1{margin:0;font-size:32px;font-weight:700;background:linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}.subtitle{color:var(--text-secondary);margin-top:8px;font-size:14px}.topbar{position:absolute;right:24px;top:32px;display:flex;gap:12px}.topbar a{width:42px;height:42px;border-radius:12px;background:var(--card-bg);border:1px solid var(--border-color);color:var(--primary);display:inline-flex;align-items:center;justify-content:center;transition:all .3s ease;box-shadow:var(--shadow)}.topbar a:hover{background:var(--primary);color:#fff;transform:translateY(-2px);box-shadow:var(--shadow-lg)}.main-card{background:var(--card-bg);border-radius:20px;padding:28px;margin-bottom:24px;box-shadow:var(--shadow-lg);border:1px solid var(--border-color);backdrop-filter:blur(10px)}.section-title{font-size:18px;font-weight:600;color:var(--primary);margin-bottom:16px;display:flex;align-items:center;gap:8px}.section-title::before{content:'';width:4px;height:20px;background:linear-gradient(180deg,var(--primary) 0%,var(--primary-light) 100%);border-radius:2px}.url-box{background:linear-gradient(135deg,#f8fafc 0%,#f1f5f9 100%);border:2px solid var(--border-color);border-radius:12px;padding:16px;font-family:'Monaco','Consolas',monospace;font-size:13px;color:var(--text-primary);word-break:break-all;position:relative;overflow:hidden}.url-box::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--primary) 0%,var(--primary-light) 100%)}.button-group{display:flex;gap:12px;margin-top:20px;flex-wrap:wrap}.btn{flex:1;min-width:120px;padding:12px 20px;border-radius:10px;border:none;font-size:14px;font-weight:600;cursor:pointer;transition:all .3s ease;display:inline-flex;align-items:center;justify-content:center;gap:6px}.btn-primary{background:linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);color:#fff;box-shadow:0 4px 14px rgba(37,99,235,0.3)}.btn-primary:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(37,99,235,0.4)}.btn-secondary{background:#fff;color:var(--primary);border:2px solid var(--border-color)}.btn-secondary:hover{transform:translateY(-2px);box-shadow:var(--shadow-lg)}.btn-success{background:linear-gradient(135deg,#10b981 0%,#34d399 100%);color:#fff;box-shadow:0 4px 14px rgba(16,185,129,0.3)}.btn-success:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(16,185,129,0.4)}.btn-danger{background:linear-gradient(135deg,#ef4444 0%,#f87171 100%);color:#fff}.btn-danger:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(239,68,68,0.4)}.form-group{margin-bottom:20px}label{display:block;margin-bottom:8px;font-weight:600;color:var(--text-primary)}input[type="text"],input[type="number"]{width:100%;padding:12px 16px;border:2px solid var(--border-color);border-radius:10px;background:#fff;color:var(--text-primary);font-size:14px;box-sizing:border-box;transition:all .3s ease}input[type="text"]:focus,input[type="number"]:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(37,99,235,0.1)}.input-group{display:flex;gap:8px}.input-group input{flex:1}.input-group .btn{flex:none;min-width:auto;padding:10px 16px;font-size:13px}.list{display:flex;flex-direction:column;gap:8px;margin-bottom:12px}.list-item{display:flex;gap:8px;align-items:center}.list-item input{flex:1}.list-item .btn{flex:none;min-width:auto;padding:8px 12px;font-size:12px}.chip{padding:6px 14px;font-size:12px;min-width:auto}.link-arrow{color:var(--primary);text-decoration:none;font-size:14px;display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:8px;background:var(--bg-gradient-end);transition:all .3s ease;margin-left:8px}.link-arrow:hover{background:var(--primary);color:#fff}.label-with-link{display:flex;align-items:center}.config-section{display:none}.config-section.active{display:block}.collapse-section{margin-bottom:16px;border:2px solid var(--border-color);border-radius:12px;overflow:hidden}.collapse-header{width:100%;padding:16px 20px;background:linear-gradient(135deg,var(--bg-gradient-start) 0%,var(--bg-gradient-end) 100%);border:none;cursor:pointer;display:flex;align-items:center;justify-content:space-between;font-size:16px;font-weight:600;color:var(--text-primary);transition:all .3s ease}.collapse-header:hover{background:linear-gradient(135deg,var(--bg-gradient-end) 0%,var(--bg-gradient-start) 100%)}.collapse-header .icon{font-size:20px;transition:transform .3s ease}.collapse-header.active .icon{transform:rotate(180deg)}.collapse-content{max-height:0;overflow:hidden;transition:max-height .3s ease,padding .3s ease;padding:0 20px}.collapse-content.active{max-height:2000px;padding:20px}.qr-modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(30,58,95,0.6);backdrop-filter:blur(4px);z-index:1000;align-items:center;justify-content:center;padding:20px}.qr-modal.active{display:flex}.qr-content{background:var(--card-bg);border-radius:24px;padding:32px;text-align:center;max-width:400px;width:100%;box-shadow:var(--shadow-lg);border:1px solid var(--border-color);position:relative}.qr-content::before{content:'';position:absolute;top:0;left:0;right:0;height:6px;background:linear-gradient(90deg,var(--primary) 0%,var(--primary-light) 100%);border-radius:24px 24px 0 0}.qr-title{font-size:20px;font-weight:600;color:var(--text-primary);margin-bottom:8px}.qr-subtitle{color:var(--text-secondary);font-size:14px;margin-bottom:20px}#qrCanvas{display:flex;justify-content:center;margin:20px 0;padding:20px;background:#fff;border-radius:16px;border:2px solid var(--border-color)}.qr-close{background:linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);color:#fff;border:none;padding:12px 32px;border-radius:10px;font-weight:600;cursor:pointer;transition:all .3s ease}.qr-close:hover{transform:translateY(-2px);box-shadow:0 4px 14px rgba(37,99,235,0.3)}.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(100px);background:var(--text-primary);color:#fff;padding:12px 24px;border-radius:10px;font-size:14px;opacity:0;transition:all .3s ease;z-index:2000}.toast.show{transform:translateX(-50%) translateY(0);opacity:1}.message{margin-top:12px;padding:12px 16px;border-radius:10px;text-align:center;font-size:14px;font-weight:500}.message.success{background:#d1fae5;border:1px solid #a7f3d0;color:#065f46}.message.error{background:#fee2e2;border:1px solid #fecaca;color:#991b1b}.spinner{display:inline-block;width:12px;height:12px;border:2px solid rgba(255,255,255,.35);border-top-color:#fff;border-radius:50%;animation:spin .8s linear infinite;margin-right:6px;vertical-align:-2px}@keyframes spin{to{transform:rotate(360deg)}}@media(max-width:640px){.wrap{padding:16px}h1{font-size:24px}.topbar{position:static;justify-content:center;margin-bottom:20px}.btn{min-width:100%;margin-bottom:8px}.tab-nav{overflow-x:auto;flex-wrap:nowrap}.tab-btn{white-space:nowrap}}</style></head><body><div class="wrap"><div class="header"><h1>✨ ZQ-NewVless</h1><div class="subtitle">安全、快速、稳定的代理服务</div></div><div class="topbar"><a class="gh" href="https://github.com/BAYUEQI/ZQ-NewVless" target="_blank" rel="nofollow noopener" aria-label="GitHub 项目"><svg viewBox="0 0 16 16" width="20" height="20" aria-hidden="true" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"></path></svg></a></div><div class="main-card"><div class="collapse-section"><button class="collapse-header active" data-collapse="sub-content"><span>📡 订阅链接</span><span class="icon">▼</span></button><div class="collapse-content active" id="sub-content"><div class="url-box">${subUrl}</div><div class="button-group"><button class="btn btn-primary copy" data-text="${subUrl}">📋 复制订阅链接</button><button class="btn btn-secondary copy" id="exportNodes">📤 导出节点信息</button><button class="btn btn-success" id="showQrBtn">📱 显示二维码</button></div></div></div><div class="collapse-section"><button class="collapse-header" data-collapse="config-content"><span>⚙️ 配置管理</span><span class="icon">▼</span></button><div class="collapse-content" id="config-content"><form id="configForm"><div class="form-group"><label for="uuid">UUID</label><input type="text" id="uuid" name="uuid" required placeholder="请输入UUID"></div><div class="form-group"><div class="label-with-link"><label>优选IP (可选)</label><a href="https://ipdb.030101.xyz/bestcfv4/" target="_blank" rel="nofollow noopener" class="link-arrow" title="优选IP地址">↗</a></div><div id="domains" class="list"></div><div class="input-group"><input type="text" id="domainNew" placeholder="输入IP后点击添加"><button type="button" id="addDomain" class="btn btn-secondary chip">➕ 添加</button></div></div><div class="form-group"><label>端口 (可选)</label><div id="ports" class="list"></div><div class="input-group"><input type="number" id="portNew" min="1" max="65535" placeholder="输入端口后点击添加"><button type="button" id="addPort" class="btn btn-secondary chip">➕ 添加</button></div></div><div class="form-group"><label for="s5">SOCKS5代理 (可选)</label><div class="input-group"><input type="text" id="s5" name="s5" placeholder="格式: user:pass@host:port 或 host:port"><button type="button" id="probeS5" class="btn btn-secondary chip">🔍 检测</button></div></div><div class="form-group"><div class="label-with-link"><label for="proxyIp">ProxyIP (可选)</label><a href="https://ipdb.030101.xyz/bestproxy/" target="_blank" rel="nofollow noopener" class="link-arrow" title="ProxyIP地址">↗</a></div><div class="input-group"><input type="text" id="proxyIp" name="proxyIp" placeholder="格式: host:port 或 host"><button type="button" id="probeProxy" class="btn btn-secondary chip">🔍 检测</button></div></div><div class="button-group"><button type="submit" class="btn btn-primary">💾 保存配置</button><button type="button" class="btn btn-secondary" onclick="loadConfig()">🔄 重新加载</button></div><div id="message" class="message" style="display:none"></div></form></div></div></div><div class="qr-modal" id="qrModal"><div class="qr-content"><div class="qr-title">📱 扫码订阅</div><div class="qr-subtitle">使用客户端扫描二维码快速添加</div><div id="qrCanvas"></div><button class="qr-close" id="closeQrBtn">关闭</button></div></div><div class="toast" id="toast"></div><script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script><script>(function(){const toastEl=document.getElementById('toast');function showToast(msg){toastEl.textContent=msg;toastEl.classList.add('show');setTimeout(()=>toastEl.classList.remove('show'),2000)}function showMessage(text,type){const el=document.getElementById('message');el.textContent=text;el.className='message '+type;el.style.display='block';setTimeout(()=>{el.style.display='none'},3000)}function fallbackCopy(text){const ta=document.createElement('textarea');ta.value=text;ta.setAttribute('readonly','');ta.style.position='absolute';ta.style.left='-9999px';document.body.appendChild(ta);ta.select();let ok=false;try{ok=document.execCommand('copy')}catch(e){}document.body.removeChild(ta);return ok}async function doCopy(btn){const t=btn.getAttribute('data-text');if(!t)return;let ok=false;if(navigator.clipboard&&navigator.clipboard.writeText){try{await navigator.clipboard.writeText(t);ok=true}catch(e){ok=false}}if(!ok){ok=fallbackCopy(t)}showToast(ok?'✅ 已复制到剪贴板':'❌ 复制失败')}document.querySelectorAll('button.copy').forEach(b=>b.addEventListener('click',e=>{doCopy(e.currentTarget)}));const exportBtn=document.getElementById('exportNodes');if(exportBtn){exportBtn.addEventListener('click',async()=>{const allNodes=${allNodesJson};const nodeText=allNodes.join('\\n')+'\\n';const nodeTextBase64=btoa(unescape(encodeURIComponent(nodeText)));let ok=false;if(navigator.clipboard&&navigator.clipboard.writeText){try{await navigator.clipboard.writeText(nodeTextBase64);ok=true}catch(e){ok=false}}if(!ok){ok=fallbackCopy(nodeTextBase64)}showToast(ok?'✅ 已导出到剪贴板':'❌ 导出失败')})}const showQrBtn=document.getElementById('showQrBtn');const qrModal=document.getElementById('qrModal');const closeQrBtn=document.getElementById('closeQrBtn');const qrCanvas=document.getElementById('qrCanvas');let qrCode=null;showQrBtn.addEventListener('click',()=>{qrModal.classList.add('active');if(!qrCode){qrCode=new QRCode(qrCanvas,{text:'${subUrl}',width:220,height:220,colorDark:'#2563eb',colorLight:'#ffffff',correctLevel:QRCode.CorrectLevel.M})}});closeQrBtn.addEventListener('click',()=>{qrModal.classList.remove('active')});qrModal.addEventListener('click',(e)=>{if(e.target===qrModal)qrModal.classList.remove('active')});const tabBtns=document.querySelectorAll('.tab-btn');const configSections=document.querySelectorAll('.config-section');tabBtns.forEach(btn=>{btn.addEventListener('click',()=>{const tab=btn.dataset.tab;tabBtns.forEach(b=>b.classList.remove('active'));configSections.forEach(s=>s.classList.remove('active'));btn.classList.add('active');document.getElementById(tab+'-section').classList.add('active')})});function renderList(container,values,placeholder,isPort){container.innerHTML='';values.forEach((val,idx)=>{const row=document.createElement('div');row.className='list-item';const input=document.createElement('input');input.type=isPort?'number':'text';if(isPort){input.min='1';input.max='65535'}input.value=String(val);input.placeholder=placeholder;const del=document.createElement('button');del.type='button';del.className='btn btn-danger chip';del.textContent='🗑️ 删除';del.addEventListener('click',()=>{values.splice(idx,1);renderList(container,values,placeholder,isPort)});row.appendChild(input);row.appendChild(del);container.appendChild(row);input.addEventListener('input',()=>{values[idx]=isPort?Number(Math.max(1,Math.min(65535,parseInt(input.value||'0',10)))):input.value.trim()})})}const state={domains:[],ports:[]};async function loadConfig(){try{const uuid=document.getElementById('uuid').value.trim()||'${userUUID}';const response=await fetch('/api/config/'+uuid);if(!response.ok)throw 0;const cfg=await response.json();document.getElementById('uuid').value=cfg.uuid||'';document.getElementById('s5').value=cfg.s5||'';document.getElementById('proxyIp').value=cfg.proxyIp||'';state.domains=Array.isArray(cfg.domains)?cfg.domains.slice():[];if((cfg.domain||'').trim())state.domains.unshift(cfg.domain.trim());state.domains=[...new Set(state.domains.filter(Boolean))];state.ports=(Array.isArray(cfg.ports)?cfg.ports:[]).map(x=>parseInt(x,10)).filter(n=>n>0&&n<=65535);if(parseInt(cfg.port,10))state.ports.unshift(parseInt(cfg.port,10));state.ports=[...new Set(state.ports)];renderList(document.getElementById('domains'),state.domains,'如: example.com 或 127.0.0.1',false);renderList(document.getElementById('ports'),state.ports,'如: 443',true);showMessage('✅ 配置加载成功','success')}catch(e){showMessage('❌ 配置加载失败','error')}}async function saveConfigForm(){const uuid=document.getElementById('uuid').value.trim();const s5=document.getElementById('s5').value.trim();const proxyIp=document.getElementById('proxyIp').value.trim();const domains=Array.from(document.querySelectorAll('#domains .list-item input')).map(i=>i.value.trim()).filter(Boolean);const ports=Array.from(document.querySelectorAll('#ports .list-item input')).map(i=>parseInt(i.value,10)).filter(n=>n>0&&n<=65535);const body={uuid,s5,proxyIp,domains,ports};const response=await fetch('/api/config/'+uuid,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});const result=await response.json();if(response.ok){showMessage('✅ '+(result.message||'配置保存成功'),'success');setTimeout(()=>{window.location.href='/'+uuid;},800);}else{showMessage('❌ '+(result.error||'配置保存失败'),'error')}}document.addEventListener('DOMContentLoaded',()=>{const collapseHeaders=document.querySelectorAll('.collapse-header');collapseHeaders.forEach(header=>{header.addEventListener('click',()=>{const targetId=header.getAttribute('data-collapse');const content=document.getElementById(targetId);const isActive=header.classList.contains('active');if(isActive){header.classList.remove('active');content.classList.remove('active')}else{header.classList.add('active');content.classList.add('active')}})});const s5Btn=document.getElementById('probeS5');const pxBtn=document.getElementById('probeProxy');const addDomain=document.getElementById('addDomain');const addPort=document.getElementById('addPort');const domainNew=document.getElementById('domainNew');const portNew=document.getElementById('portNew');addDomain&&addDomain.addEventListener('click',()=>{const v=(domainNew.value||'').trim();if(!v)return;state.domains.push(v);renderList(document.getElementById('domains'),state.domains,'如: example.com',false);domainNew.value=''});addPort&&addPort.addEventListener('click',()=>{const n=parseInt(portNew.value||'0',10);if(!n||n<1||n>65535)return;state.ports.push(n);renderList(document.getElementById('ports'),state.ports,'如: 443',true);portNew.value=''});const runProbe=async(btn,url,label)=>{if(!btn)return;btn.disabled=true;btn.innerHTML='<span class="spinner"></span>'+label;let res;try{const r=await fetch(url);res=await r.json()}catch{res={ok:false,message:'接口错误'}}btn.disabled=false;btn.innerHTML='🔍 检测';return res};if(s5Btn){s5Btn.addEventListener('click',async(e)=>{e.preventDefault();const timeout=1000;const uuid=document.getElementById('uuid').value.trim()||'${userUUID}';const valEl=document.getElementById('s5');const val=(valEl&&valEl.value||'').trim();const q='&uuid='+encodeURIComponent(uuid)+(val?('&s5='+encodeURIComponent(val)):'');const res=await runProbe(s5Btn,'/api/probe?type=s5&timeout='+timeout+q,'检测中');showMessage((res.ok?'✅':'❌')+' SOCKS5：'+(res.ok?'可用':'不可用')+' ('+(res.ms||'-')+'ms) '+(res.message||''),res.ok?'success':'error')})}if(pxBtn){pxBtn.addEventListener('click',async(e)=>{e.preventDefault();const timeout=1000;const uuid=document.getElementById('uuid').value.trim()||'${userUUID}';const valEl=document.getElementById('proxyIp');const val=(valEl&&valEl.value||'').trim();const q='&uuid='+encodeURIComponent(uuid)+(val?('&proxyip='+encodeURIComponent(val)):'');const res=await runProbe(pxBtn,'/api/probe?type=proxyip&timeout='+timeout+q,'检测中');showMessage((res.ok?'✅':'❌')+' ProxyIP：'+(res.ok?'可用':'不可用')+' ('+(res.ms||'-')+'ms) '+(res.message||''),res.ok?'success':'error')})}});document.getElementById('configForm').addEventListener('submit',function(e){e.preventDefault();saveConfigForm()});loadConfig()})()</script></body></html>`;
			return new Response(html, {headers:{'content-type':'text/html; charset=utf-8'}});
		}
		return new Response('Not Found', { status: 404 });
	}
};
