import { connect } from "cloudflare:sockets";

function trojanpwd(s) {
    const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
    s = unescape(encodeURIComponent(s));
    const l = s.length * 8;
    s += String.fromCharCode(0x80);
    while ((s.length * 8) % 512 !== 448) {
        s += String.fromCharCode(0);
    }
    const h = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
        0xbefa4fa4,
    ];
    const hi = Math.floor(l / 0x100000000);
    const lo = l & 0xffffffff;
    s += String.fromCharCode(
        (hi >>> 24) & 0xff,
        (hi >>> 16) & 0xff,
        (hi >>> 8) & 0xff,
        hi & 0xff,
        (lo >>> 24) & 0xff,
        (lo >>> 16) & 0xff,
        (lo >>> 8) & 0xff,
        lo & 0xff,
    );
    const w = [];
    for (let i = 0; i < s.length; i += 4) {
        w.push(
            (s.charCodeAt(i) << 24) |
                (s.charCodeAt(i + 1) << 16) |
                (s.charCodeAt(i + 2) << 8) |
                s.charCodeAt(i + 3),
        );
    }
    for (let i = 0; i < w.length; i += 16) {
        const x = new Array(64).fill(0);
        for (let j = 0; j < 16; j++) {
            x[j] = w[i + j];
        }
        for (let j = 16; j < 64; j++) {
            const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
            const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
            x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
        }
        let [a, b, c, d, e, f, g, h0] = h;
        for (let j = 0; j < 64; j++) {
            const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25);
            const ch = (e & f) ^ (~e & g);
            const t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
            const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (S0 + maj) >>> 0;
            h0 = g;
            g = f;
            f = e;
            e = (d + t1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (t1 + t2) >>> 0;
        }
        for (let j = 0; j < 8; j++) {
            h[j] = (h[j] + [a, b, c, d, e, f, g, h0][j]) >>> 0;
        }
    }
    let hex = "";
    for (let i = 0; i < 7; i++) {
        for (let j = 24; j >= 0; j -= 8) {
            hex += ((h[i] >>> j) & 0xff).toString(16).padStart(2, "0");
        }
    }
    return hex;
}

function parseTrojanRequest(buffer, pwd) {
    const p = trojanpwd(pwd);
    if (buffer.byteLength < 56) {
        return { hasError: true, message: "invalid data" };
    }
    const b = new Uint8Array(buffer);
    if (b[56] !== 0x0d || b[57] !== 0x0a) {
        return { hasError: true, message: "invalid header" };
    }
    if (new TextDecoder().decode(buffer.slice(0, 56)) !== p) {
        return { hasError: true, message: "invalid password" };
    }
    const s5buf = buffer.slice(58);
    if (s5buf.byteLength < 6) {
        return { hasError: true, message: "invalid S5 data" };
    }
    const v = new DataView(s5buf);
    const cmd = v.getUint8(0);
    if (cmd !== 1 && cmd !== 3) {
        return { hasError: true, message: "unsupported cmd" };
    }
    const at = v.getUint8(1);
    const isUDP = cmd === 3;
    let addr = "";
    let ai = 2;
    let al = 0;
    if (at === 1) {
        al = 4;
        addr = new Uint8Array(s5buf.slice(ai, ai + al)).join(".");
    } else if (at === 3) {
        al = v.getUint8(ai);
        ai++;
        addr = new TextDecoder().decode(s5buf.slice(ai, ai + al));
    } else if (at === 4) {
        al = 16;
        const dv = new DataView(s5buf.slice(ai, ai + al));
        const ip6 = [];
        for (let i = 0; i < 8; i++) {
            ip6.push(dv.getUint16(i * 2).toString(16));
        }
        addr = ip6.join(":");
    } else {
        return { hasError: true, message: "invalid atype" };
    }
    if (!addr) {
        return { hasError: true, message: "empty addr" };
    }
    const pi = ai + al;
    const port = v.getUint16(pi);
    return {
        hasError: false,
        addressType: at,
        port: port,
        hostname: addr,
        isUDP: isUDP,
        rawClientData: s5buf.slice(pi + 4),
    };
}

const text = (c, s = 200) =>
    new Response(c, { status: s, headers: { "content-type": "text/plain; charset=utf-8" } });
const json = (c, s = 200) =>
    new Response(JSON.stringify(c), {
        status: s,
        headers: { "content-type": "application/json; charset=utf-8" },
    });
const b64e = (s) => {
    const e = new TextEncoder(),
        b = e.encode(s);
    return btoa(String.fromCharCode(...new Uint8Array(b)));
};
const randStr = () => Math.random().toString(36).slice(2, 8);
const paths = [
    "/static/js",
    "/assets/img",
    "/api/2024",
    "/cdn/file",
    "/upload/data",
    "/media/v2",
    "/lib/ext",
    "/res/now",
    "/stat/click",
    "/track/log",
    "/api/v1/data",
    "/css/main",
    "/js/app",
    "/fonts/google",
    "/images/hero",
    "/videos/intro",
    "/api/v2/user",
    "/assets/css",
    "/static/media",
    "/build/js",
    "/dist/css",
    "/public/img",
    "/content/data",
    "/files/doc",
    "/download/pkg",
    "/api/v3/item",
    "/resource/img",
];
const paramsMap = {
    t: ["m", "type", "mode"],
    d: ["dir", "direct", "d"],
    s: ["socks", "proxy", "s"],
    p: ["ip", "proxyip", "p"],
    v: ["r", "rand", "v", "id", "t"],
};
const getPath = () => paths[Math.floor(Math.random() * paths.length)];
const getParam = (key) => paramsMap[key][Math.floor(Math.random() * paramsMap[key].length)];

function parseProxyAddress(proxyStr) {
    if (!proxyStr) return null;
    proxyStr = proxyStr.trim();
    if (proxyStr.startsWith("socks://") || proxyStr.startsWith("socks5://")) {
        try {
            const url = new URL(proxyStr.replace(/^socks:\/\//, "socks5://"));
            if (!url.port) return null;
            return {
                type: "socks5",
                host: url.hostname,
                port: +url.port,
                username: url.username ? decodeURIComponent(url.username) : "",
                password: url.password ? decodeURIComponent(url.password) : "",
            };
        } catch {
            return null;
        }
    }
    if (proxyStr.includes("@")) {
        const [cred, server] = proxyStr.split("@"),
            [user, pass] = cred.split(":"),
            [host, port] = server.split(":");
        if (host && port)
            return { type: "socks5", host, port: +port, username: user, password: pass };
    } else if (proxyStr.includes(":")) {
        const [host, port] = proxyStr.split(":");
        if (host && port) return { type: "socks5", host, port: +port, username: "", password: "" };
    }
    return null;
}

async function socks5Connect(socket, proxyConfig, targetHost, targetPort, timeoutMs) {
    const writer = socket.writable.getWriter(),
        reader = socket.readable.getReader();
    try {
        const authMethods =
            proxyConfig.username && proxyConfig.password
                ? new Uint8Array([0x05, 0x02, 0x00, 0x02])
                : new Uint8Array([0x05, 0x01, 0x00]);
        await writer.write(authMethods);
        let res = await Promise.race([
            reader.read(),
            new Promise((r) => setTimeout(() => r({ timeout: true }), timeoutMs)),
        ]);
        if (!res || res.timeout) throw new Error("SOCKS5 timeout");
        const method = new Uint8Array(res.value)[1];
        if (method === 0x02) {
            if (!proxyConfig.username || !proxyConfig.password)
                throw new Error("SOCKS5 auth required");
            const uBytes = new TextEncoder().encode(proxyConfig.username),
                pBytes = new TextEncoder().encode(proxyConfig.password);
            const auth = new Uint8Array(3 + uBytes.length + pBytes.length);
            auth[0] = 0x01;
            auth[1] = uBytes.length;
            auth.set(uBytes, 2);
            auth[2 + uBytes.length] = pBytes.length;
            auth.set(pBytes, 3 + uBytes.length);
            await writer.write(auth);
            res = await Promise.race([
                reader.read(),
                new Promise((r) => setTimeout(() => r({ timeout: true }), timeoutMs)),
            ]);
            if (!res || res.timeout || new Uint8Array(res.value)[1] !== 0x00)
                throw new Error("SOCKS5 auth failed");
        } else if (method !== 0x00) throw new Error(`SOCKS5 unsupported method: ${method}`);
        const hostBytes = new TextEncoder().encode(targetHost);
        const connect = new Uint8Array(7 + hostBytes.length);
        connect[0] = 0x05;
        connect[1] = 0x01;
        connect[2] = 0x00;
        connect[3] = 0x03;
        connect[4] = hostBytes.length;
        connect.set(hostBytes, 5);
        new DataView(connect.buffer).setUint16(5 + hostBytes.length, targetPort, false);
        await writer.write(connect);
        res = await Promise.race([
            reader.read(),
            new Promise((r) => setTimeout(() => r({ timeout: true }), timeoutMs)),
        ]);
        if (!res || res.timeout || new Uint8Array(res.value)[1] !== 0x00)
            throw new Error("SOCKS5 connect failed");
        return { writer, reader };
    } catch (e) {
        writer.releaseLock();
        reader.releaseLock();
        throw e;
    }
}

const connectDirect = async (hostname, portNum, data) => {
    const sock = connect({ hostname, port: portNum });
    await sock.opened;
    const w = sock.writable.getWriter();
    await w.write(data);
    w.releaseLock();
    return sock;
};

const connectStreams = async (remoteSocket, webSocket, headerData, retryFunc, userCfg) => {
    let header = headerData,
        hasData = false,
        dataPromiseResolve;
    const dataPromise = new Promise((resolve) => (dataPromiseResolve = resolve));
    const timeoutId = setTimeout(() => {
        if (!hasData) dataPromiseResolve(false);
    }, userCfg?.fallbackTimeout || 100);
    remoteSocket.readable
        .pipeTo(
            new WritableStream({
                async write(chunk, controller) {
                    clearTimeout(timeoutId);
                    hasData = true;
                    dataPromiseResolve(true);
                    if (webSocket.readyState !== 1) controller.error("ws not open");
                    if (header) {
                        const response = new Uint8Array(header.length + chunk.byteLength);
                        response.set(header, 0);
                        response.set(chunk, header.length);
                        webSocket.send(headerData ? response.buffer : chunk);
                        header = null;
                    } else {
                        webSocket.send(chunk);
                    }
                },
                abort() {},
            }),
        )
        .catch(() => {
            try {
                webSocket.readyState === 1 && webSocket.close();
            } catch {}
        });
    const receivedData = await dataPromise;
    if (!receivedData && retryFunc) await retryFunc();
};

const connectParallel = async (
    host,
    port,
    payload,
    order,
    mode,
    proxyCfg,
    proxyIp,
    getOrderFn,
    tryConnectFn,
    ws,
    header,
    userCfg,
    remoteVar,
    setRemote,
    retryFn,
) => {
    const tryConnect = async (type) => {
        try {
            if (type === "direct") return await connectDirect(host, port, payload);
            if (type === "s5" && proxyCfg) return await tryConnectFn(proxyCfg, host, port, payload);
            if (type === "proxy" && proxyIp) {
                const [ph, pp = port] = proxyIp.split(":");
                return await connectDirect(ph, +pp || port, payload);
            }
        } catch {}
        return null;
    };
    const tryNext = async (index) => {
        if (index >= order.length) return null;
        const sock = await tryConnect(order[index]);
        return sock || (await tryNext(index + 1));
    };
    if (mode === "s5") {
        if (proxyCfg) {
            const sock = await tryConnect("s5");
            if (sock) {
                setRemote(sock);
                await connectStreams(sock, ws, header, null, userCfg);
            }
        }
        return;
    }
    const primary = await tryConnect(order[0]);
    if (!primary) {
        const backup = await tryNext(1);
        if (backup) {
            setRemote(backup);
            await connectStreams(backup, ws, header, null, userCfg);
        }
        return;
    }
    setRemote(primary);
    const retryFunc =
        order.length > 1
            ? async () => {
                  const backup = await tryNext(1);
                  if (backup) {
                      try {
                          primary.close();
                      } catch {}
                      setRemote(backup);
                      await connectStreams(backup, ws, header, null, userCfg);
                  }
              }
            : null;
    await connectStreams(primary, ws, header, retryFunc, userCfg);
};

export default {
    async fetch(req, env) {
        const getUserConfig = async () => {
            try {
                const config = await env.VTPanel?.get("user_config", "json");
                const merged = config || {
                    uuid: "ef9d104e-ca0e-4202-ba4b-a0afb969c747",
                    domain: "",
                    port: "443",
                    s5: "",
                    proxyIp: "",
                    domains: [],
                    ports: [],
                    fallbackTimeout: 100,
                };
                // 兼容旧格式：将字符串数组转换为对象数组
                if (Array.isArray(merged.domains)) {
                    merged.domains = merged.domains.map((item) => {
                        if (typeof item === "string") {
                            return { ip: item, remark: "" };
                        }
                        return item;
                    });
                } else {
                    merged.domains = [];
                }
                merged.ports = Array.isArray(merged.ports) ? merged.ports : [];
                merged.fallbackTimeout =
                    typeof merged.fallbackTimeout === "number"
                        ? Math.max(1, Math.min(5000, merged.fallbackTimeout))
                        : 100;
                const d = (merged.domain || "").trim();
                if (d && !merged.domains.some((x) => x.ip === d))
                    merged.domains.unshift({ ip: d, remark: "" });
                const pNum = Math.max(
                    1,
                    Math.min(65535, parseInt(merged.port || "443", 10) || 443),
                );
                if (!merged.ports.some((x) => +x === pNum)) merged.ports.push(pNum);
                return merged;
            } catch {
                return {
                    uuid: "ef9d104e-ca0e-4202-ba4b-a0afb969c747",
                    domain: "",
                    port: "443",
                    s5: "",
                    proxyIp: "",
                    domains: [],
                    ports: [443],
                    fallbackTimeout: 100,
                };
            }
        };

        const buildPath = (t, d, s, p) => {
            const params = [];
            if (t) params.push(`${getParam("t")}=${t}`);
            if (d) params.push(`${getParam("d")}=1`);
            if (s) params.push(`${getParam("s")}=${encodeURIComponent(s)}`);
            if (p) params.push(`${getParam("p")}=${encodeURIComponent(p)}`);
            params.push(`${getParam("v")}=${randStr()}`);
            return `${getPath()}?${params.join("&")}`;
        };

        const buildVlessUri = (rawPathQuery, uuid, label, workerHost, preferredDomain, port) =>
            `vless://${uuid}@${preferredDomain}:${port}?encryption=none&security=tls&sni=${workerHost}&type=ws&host=${workerHost}&path=${encodeURIComponent(rawPathQuery)}&fp=chrome#${encodeURIComponent(label || preferredDomain)}`;
        const buildTrojanUri = (rawPathQuery, uuid, label, workerHost, preferredDomain, port) =>
            `trojan://${uuid}@${preferredDomain}:${port}?security=tls&sni=${workerHost}&type=ws&host=${workerHost}&path=${encodeURIComponent(rawPathQuery)}#${encodeURIComponent(label || preferredDomain)}`;

        const buildVariants = (s5, proxyIp) => {
            const v = [{ label: "直连", raw: buildPath("d", 1, null, null) }];
            if (s5) {
                v.push({ label: "SOCKS5", raw: buildPath("s", null, s5, null) });
                v.push({ label: "直连+SOCKS5", raw: buildPath("p", 1, s5, null) });
            }
            if (proxyIp) v.push({ label: "直连+ProxyIP", raw: buildPath("p", 1, null, proxyIp) });
            if (s5 && proxyIp)
                v.push({ label: "直连+SOCKS5+ProxyIP", raw: buildPath("p", 1, s5, proxyIp) });
            return v;
        };

        const getDomainPortLists = (request, cfg) => {
            const workerHost = new URL(request.url).hostname;
            const domains = [
                ...new Map(
                    (cfg.domains || []).filter((x) => x && x.ip).map((x) => [x.ip, x]),
                ).values(),
            ];
            if (!domains.length)
                domains.push({ ip: (cfg.domain || workerHost).trim() || workerHost, remark: "" });
            const ports = [
                ...new Set(
                    (cfg.ports || [])
                        .concat(cfg.port || [])
                        .map((p) => Math.max(1, Math.min(65535, +p || 443))),
                ),
            ];
            if (!ports.length) ports.push(443);
            return { workerHost, domains, ports };
        };

        if (req.headers.get("Upgrade")?.toLowerCase() === "websocket") {
            const u = new URL(req.url);
            const userConfig = await getUserConfig();
            const [client, ws] = Object.values(new WebSocketPair());
            ws.accept();

            if (u.pathname.includes("%3F")) {
                const decoded = decodeURIComponent(u.pathname);
                const queryIndex = decoded.indexOf("?");
                if (queryIndex !== -1) {
                    u.search = decoded.slice(queryIndex);
                    u.pathname = decoded.slice(0, queryIndex);
                }
            }

            const getParamValue = (keys) => {
                for (const k of keys) {
                    const v = u.searchParams.get(k);
                    if (v !== null) return v;
                }
                return null;
            };
            const modeMap = { d: "direct", s: "s5", p: "parallel" };
            const modeVal = getParamValue(["t", "m", "type", "mode"]);
            const mode = modeMap[modeVal] || "parallel";
            const s5Param = getParamValue(["s", "socks", "proxy"]);
            const proxyParam = getParamValue(["p", "ip", "proxyip"]);
            let proxyConfig = s5Param ? parseProxyAddress(s5Param) : null;
            if (!proxyConfig && s5Param) {
                const path = s5Param;
                if (path.includes("@")) {
                    const [cred, server] = path.split("@"),
                        [user, pass] = cred.split(":"),
                        [host, port] = server.split(":");
                    if (host && port)
                        proxyConfig = {
                            type: "socks5",
                            host,
                            port: +port,
                            username: user,
                            password: pass,
                        };
                } else if (path.includes(":")) {
                    const [host, port] = path.split(":");
                    if (host && port)
                        proxyConfig = {
                            type: "socks5",
                            host,
                            port: +port,
                            username: "",
                            password: "",
                        };
                }
            }
            const PROXY_IP = proxyParam ? String(proxyParam) : null;

            const getOrder = () => {
                if (mode === "s5") return ["s5"];
                const order = [];
                const params = u.search.slice(1).split("&");
                for (const pair of params) {
                    const key = pair.split("=")[0];
                    if (["d", "dir", "direct"].includes(key)) order.push("direct");
                    if (["s", "socks", "proxy"].includes(key)) order.push("s5");
                    if (["p", "ip", "proxyip"].includes(key)) order.push("proxy");
                }
                if (order.length === 0 && PROXY_IP) return ["proxy", "direct"];
                return order.length ? order : ["direct"];
            };

            let remote = null,
                udpWriter = null,
                isDNS = false,
                isTrojan = false,
                trojanUDPCtx = null;

            const connect2Socks5 = async (proxyConfig, targetHost, targetPort, initialData) => {
                const { host, port } = proxyConfig;
                const socket = connect({ hostname: host, port });
                try {
                    const { writer, reader } = await socks5Connect(
                        socket,
                        proxyConfig,
                        targetHost,
                        targetPort,
                        2500,
                    );
                    await writer.write(initialData);
                    writer.releaseLock();
                    reader.releaseLock();
                    return socket;
                } catch (error) {
                    try {
                        socket.close();
                    } catch (e) {}
                    throw error;
                }
            };

            const setRemote = (val) => (remote = val);

            const processTrojanUDP = async (chunk) => {
                if (!trojanUDPCtx) {
                    trojanUDPCtx = { cache: new Uint8Array(0) };
                }
                const curr = new Uint8Array(chunk);
                const input = trojanUDPCtx.cache.byteLength
                    ? new Uint8Array([...trojanUDPCtx.cache, ...curr])
                    : curr;

                let cursor = 0;
                while (cursor < input.byteLength) {
                    const at = input[cursor];
                    let ac = cursor + 1;
                    let al = 0;

                    if (at === 1) {
                        al = 4;
                    } else if (at === 4) {
                        al = 16;
                    } else if (at === 3) {
                        if (input.byteLength < ac + 1) break;
                        al = 1 + input[ac];
                    } else {
                        break;
                    }

                    const pc = ac + al;
                    if (input.byteLength < pc + 6) break;

                    const port = (input[pc] << 8) | input[pc + 1];
                    const pl = (input[pc + 2] << 8) | input[pc + 3];

                    if (input[pc + 4] !== 0x0d || input[pc + 5] !== 0x0a) break;

                    const ps = pc + 6;
                    const pe = ps + pl;
                    if (input.byteLength < pe) break;

                    const ah = input.slice(cursor, pc + 2);
                    const payload = input.slice(ps, pe);
                    cursor = pe;

                    if (port !== 53) continue;

                    let q = payload;
                    if (
                        payload.byteLength < 2 ||
                        ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2
                    ) {
                        q = new Uint8Array(payload.byteLength + 2);
                        q[0] = (payload.byteLength >>> 8) & 0xff;
                        q[1] = payload.byteLength & 0xff;
                        q.set(payload, 2);
                    }

                    const rc = { cache: new Uint8Array(0) };
                    const ts = new TransformStream({
                        transform(c, ctrl) {
                            const cr = new Uint8Array(c);
                            const ir = rc.cache.byteLength
                                ? new Uint8Array([...rc.cache, ...cr])
                                : cr;

                            let rcursor = 0;
                            while (rcursor + 2 <= ir.byteLength) {
                                const dl = (ir[rcursor] << 8) | ir[rcursor + 1];
                                const ds = rcursor + 2;
                                const de = ds + dl;

                                if (de > ir.byteLength) break;

                                const dp = ir.slice(ds, de);
                                const f = new Uint8Array(ah.byteLength + 4 + dp.byteLength);

                                f.set(ah, 0);
                                f[ah.byteLength] = (dp.byteLength >>> 8) & 0xff;
                                f[ah.byteLength + 1] = dp.byteLength & 0xff;
                                f[ah.byteLength + 2] = 0x0d;
                                f[ah.byteLength + 3] = 0x0a;
                                f.set(dp, ah.byteLength + 4);

                                ctrl.enqueue(f);
                                rcursor = de;
                            }
                            rc.cache = ir.slice(rcursor);
                        },
                    });

                    ts.readable.pipeTo(
                        new WritableStream({
                            async write(r) {
                                if (ws.readyState === 1) {
                                    ws.send(r);
                                }
                            },
                        }),
                    );

                    const w = ts.writable.getWriter();
                    try {
                        const resp = await fetch("https://1.1.1.1/dns-query", {
                            method: "POST",
                            headers: { "content-type": "application/dns-message" },
                            body: q,
                        });
                        await w.write(await resp.arrayBuffer());
                    } catch {}

                    w.releaseLock();
                }
                trojanUDPCtx.cache = input.slice(cursor);
            };

            new ReadableStream({
                start(ctrl) {
                    ws.addEventListener("message", (e) => ctrl.enqueue(e.data));
                    ws.addEventListener("close", () => {
                        remote?.close();
                        ctrl.close();
                    });
                    ws.addEventListener("error", () => {
                        remote?.close();
                        ctrl.error();
                    });
                    const early = req.headers.get("sec-websocket-protocol");
                    if (early) {
                        try {
                            const processed = early.replace(/-/g, "+").replace(/_/g, "/");
                            ctrl.enqueue(
                                Uint8Array.from(atob(processed), (c) => c.charCodeAt(0)).buffer,
                            );
                        } catch {}
                    }
                },
            })
                .pipeTo(
                    new WritableStream({
                        async write(data) {
                            if (isTrojan && isDNS) return processTrojanUDP(data);
                            if (isDNS) return udpWriter?.write(data);
                            if (remote) {
                                const w = remote.writable.getWriter();
                                await w.write(data);
                                w.releaseLock();
                                return;
                            }
                            if (data.byteLength >= 58) {
                                const trojanResult = parseTrojanRequest(data, userConfig.uuid);
                                if (!trojanResult.hasError) {
                                    isTrojan = true;
                                    const { hostname, port, isUDP, rawClientData } = trojanResult;
                                    if (isUDP) {
                                        if (port !== 53) return;
                                        isDNS = true;
                                        if (rawClientData.byteLength)
                                            await processTrojanUDP(rawClientData);
                                        return;
                                    }
                                    const trojanConnectStreams = async (remoteSock, webSocket) => {
                                        remoteSock.readable
                                            .pipeTo(
                                                new WritableStream({
                                                    async write(chunk) {
                                                        if (webSocket.readyState === 1)
                                                            webSocket.send(chunk);
                                                    },
                                                    abort() {},
                                                }),
                                            )
                                            .catch(() => {});
                                    };
                                    const tryConnect = async (type) => {
                                        try {
                                            if (type === "direct")
                                                return await connectDirect(
                                                    hostname,
                                                    port,
                                                    rawClientData,
                                                );
                                            if (type === "s5" && proxyConfig)
                                                return await connect2Socks5(
                                                    proxyConfig,
                                                    hostname,
                                                    port,
                                                    rawClientData,
                                                );
                                            if (type === "proxy" && PROXY_IP) {
                                                const [ph, pp = port] = PROXY_IP.split(":");
                                                return await connectDirect(
                                                    ph,
                                                    +pp || port,
                                                    rawClientData,
                                                );
                                            }
                                        } catch {}
                                        return null;
                                    };
                                    const order = getOrder();
                                    const tryNext = async (index) => {
                                        if (index >= order.length) return null;
                                        const sock = await tryConnect(order[index]);
                                        return sock || (await tryNext(index + 1));
                                    };
                                    if (mode === "s5" && proxyConfig) {
                                        const sock = await tryConnect("s5");
                                        if (sock) {
                                            remote = sock;
                                            await trojanConnectStreams(sock, ws);
                                        }
                                        return;
                                    }
                                    const primary = await tryConnect(order[0]);
                                    if (!primary) {
                                        const backup = await tryNext(1);
                                        if (backup) {
                                            remote = backup;
                                            await trojanConnectStreams(backup, ws);
                                        }
                                        return;
                                    }
                                    remote = primary;
                                    await trojanConnectStreams(primary, ws);
                                    return;
                                }
                            }
                            if (data.byteLength < 24) return;
                            const uuidBytes = new Uint8Array(data.slice(1, 17));
                            const expectedUUID = userConfig.uuid.replace(/-/g, "");
                            for (let i = 0; i < 16; i++) {
                                if (uuidBytes[i] !== parseInt(expectedUUID.substr(i * 2, 2), 16))
                                    return;
                            }
                            const view = new DataView(data);
                            const optLen = view.getUint8(17);
                            const cmd = view.getUint8(18 + optLen);
                            if (cmd !== 1 && cmd !== 2) return;
                            let pos = 19 + optLen;
                            const port = view.getUint16(pos);
                            const type = view.getUint8(pos + 2);
                            pos += 3;
                            let addr = "";
                            if (type === 1) {
                                addr = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
                                pos += 4;
                            } else if (type === 2) {
                                const len = view.getUint8(pos++);
                                addr = new TextDecoder().decode(data.slice(pos, pos + len));
                                pos += len;
                            } else if (type === 3) {
                                const ipv6 = [];
                                for (let i = 0; i < 8; i++, pos += 2)
                                    ipv6.push(view.getUint16(pos).toString(16));
                                addr = ipv6.join(":");
                            } else return;
                            const header = new Uint8Array([data[0], 0]);
                            const payload = data.slice(pos);
                            if (cmd === 2) {
                                if (port !== 53) return;
                                isDNS = true;
                                let sent = false;
                                const { readable, writable } = new TransformStream({
                                    transform(chunk, ctrl) {
                                        for (let i = 0; i < chunk.byteLength; ) {
                                            const len = new DataView(
                                                chunk.slice(i, i + 2),
                                            ).getUint16(0);
                                            ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
                                            i += 2 + len;
                                        }
                                    },
                                });
                                readable.pipeTo(
                                    new WritableStream({
                                        async write(query) {
                                            try {
                                                const resp = await fetch(
                                                    "https://1.1.1.1/dns-query",
                                                    {
                                                        method: "POST",
                                                        headers: {
                                                            "content-type":
                                                                "application/dns-message",
                                                        },
                                                        body: query,
                                                    },
                                                );
                                                if (ws.readyState === 1) {
                                                    const result = new Uint8Array(
                                                        await resp.arrayBuffer(),
                                                    );
                                                    ws.send(
                                                        new Uint8Array([
                                                            ...(sent ? [] : header),
                                                            result.length >> 8,
                                                            result.length & 0xff,
                                                            ...result,
                                                        ]),
                                                    );
                                                    sent = true;
                                                }
                                            } catch {}
                                        },
                                    }),
                                );
                                udpWriter = writable.getWriter();
                                return udpWriter.write(payload);
                            }
                            await connectParallel(
                                addr,
                                port,
                                payload,
                                getOrder(),
                                mode,
                                proxyConfig,
                                PROXY_IP,
                                getOrder,
                                connect2Socks5,
                                ws,
                                header,
                                userConfig,
                                remote,
                                setRemote,
                                null,
                            );
                        },
                    }),
                )
                .catch(() => {});

            return new Response(null, { status: 101, webSocket: client });
        }

        const url = new URL(req.url);

        if (url.pathname.startsWith("/api/config/")) {
            const pathParts = url.pathname.split("/").filter((p) => p);
            const urlUUID = pathParts[2];
            if (!urlUUID) return json({ error: "UUID不能为空" }, 400);
            const userConfig = await getUserConfig();
            if (req.method === "GET") {
                if (urlUUID !== userConfig.uuid) return json({ error: "UUID错误，无权访问" }, 403);
                return json(userConfig);
            } else if (req.method === "POST") {
                try {
                    const incoming = await req.json();
                    if (!incoming.uuid || typeof incoming.uuid !== "string")
                        return json({ error: "UUID不能为空" }, 400);
                    if (urlUUID !== userConfig.uuid && urlUUID !== incoming.uuid)
                        return json({ error: "UUID错误，无权访问" }, 403);
                    let domains = Array.isArray(incoming.domains)
                        ? incoming.domains
                              .map((x) => {
                                  if (typeof x === "object" && x !== null) {
                                      return {
                                          ip: (x.ip || "").trim(),
                                          remark: (x.remark || "").trim(),
                                      };
                                  } else if (typeof x === "string") {
                                      return { ip: x.trim(), remark: "" };
                                  }
                                  return null;
                              })
                              .filter((x) => x && x.ip)
                        : [];
                    if (incoming.domain) {
                        const d = (incoming.domain + "").trim();
                        if (d && !domains.some((x) => x.ip === d))
                            domains.unshift({ ip: d, remark: "" });
                    }
                    let ports = Array.isArray(incoming.ports)
                        ? incoming.ports.map((x) =>
                              Math.max(1, Math.min(65535, parseInt(x + "", 10) || 443)),
                          )
                        : [];
                    if (incoming.port) {
                        const pn = Math.max(
                            1,
                            Math.min(65535, parseInt(incoming.port + "", 10) || 443),
                        );
                        if (!ports.includes(pn)) ports.unshift(pn);
                    }
                    const fallbackTimeout =
                        typeof incoming.fallbackTimeout === "number"
                            ? Math.max(1, Math.min(5000, incoming.fallbackTimeout))
                            : 100;
                    const uniqueIps = new Set();
                    domains = domains.filter((x) => {
                        if (uniqueIps.has(x.ip)) return false;
                        uniqueIps.add(x.ip);
                        return true;
                    });
                    ports = [...new Set(ports)];
                    if (!domains.length) domains.push({ ip: "", remark: "" });
                    if (!ports.length) ports.push(443);
                    const normalized = {
                        uuid: incoming.uuid,
                        domain: domains[0]?.ip || "",
                        port: String(ports[0] || 443),
                        s5: incoming.s5 || "",
                        proxyIp: incoming.proxyIp || "",
                        domains: domains,
                        ports: ports,
                        fallbackTimeout,
                    };
                    if (env.VTPanel)
                        await env.VTPanel.put("user_config", JSON.stringify(normalized));
                    return json({ success: true, message: "配置保存成功" });
                } catch {
                    return json({ error: "配置保存失败" }, 500);
                }
            }
        }

        if (url.pathname.startsWith("/sub")) {
            const parts = url.pathname.split("/").filter((p) => p);
            const inputUUID = url.searchParams.get("uuid") || parts[1];
            if (!inputUUID) return new Response("missing uuid", { status: 400 });
            const userConfig = await getUserConfig();
            if (inputUUID !== userConfig.uuid) return new Response("Not Found", { status: 404 });
            const { workerHost, domains, ports } = getDomainPortLists(req, userConfig);
            const variants = buildVariants(userConfig.s5, userConfig.proxyIp);
            const ua = (req.headers.get("User-Agent") || "").toLowerCase();
            const isSubConverterRequest =
                url.searchParams.has("b64") ||
                url.searchParams.has("base64") ||
                req.headers.get("subconverter-request") ||
                req.headers.get("subconverter-version") ||
                ua.includes("subconverter");
            let 订阅类型 = isSubConverterRequest
                ? "mixed"
                : url.searchParams.has("target")
                  ? url.searchParams.get("target")
                  : url.searchParams.has("clash") ||
                      ua.includes("clash") ||
                      ua.includes("meta") ||
                      ua.includes("mihomo")
                    ? "clash"
                    : url.searchParams.has("sb") ||
                        url.searchParams.has("singbox") ||
                        ua.includes("singbox") ||
                        ua.includes("sing-box")
                      ? "singbox"
                      : url.searchParams.has("surge") || ua.includes("surge")
                        ? "surge&ver=4"
                        : url.searchParams.has("quanx") || ua.includes("quantumult")
                          ? "quanx"
                          : url.searchParams.has("loon") || ua.includes("loon")
                            ? "loon"
                            : "mixed";
            const out = [];
            for (const d of domains) {
                for (const p of ports) {
                    for (const v of variants) {
                        const displayName = d.remark ? d.remark : `${v.label} ${d.ip}:${p}`;
                        const trojanDisplayName = d.remark
                            ? `${d.remark}`
                            : `${v.label}  ${d.ip}:${p}`;
                        out.push(
                            buildVlessUri(v.raw, userConfig.uuid, displayName, workerHost, d.ip, p),
                        );
                        out.push(
                            buildTrojanUri(
                                v.raw,
                                userConfig.uuid,
                                trojanDisplayName,
                                workerHost,
                                d.ip,
                                p,
                            ),
                        );
                    }
                }
            }
            const nodesContent = out.join("\n");
            const responseHeaders = {
                "content-type": "text/plain; charset=utf-8",
                "Profile-Update-Interval": "3",
                "Profile-web-page-url": new URL(req.url).origin + "/" + userConfig.uuid,
                "Cache-Control": "no-store",
                "Content-Disposition": "attachment; filename=vtpanel",
            };
            if (订阅类型 === "mixed") {
                return new Response(b64e(nodesContent) + "\n", {
                    status: 200,
                    headers: responseHeaders,
                });
            } else {
                const encodedNodes = b64e(nodesContent);
                const 订阅转换URL = `https://subapi.vpnjacky.dpdns.org/sub?target=${订阅类型}&url=${encodeURIComponent(encodedNodes)}&emoji=false&insert=false`;
                try {
                    const response = await fetch(订阅转换URL, {
                        headers: { "User-Agent": "Subconverter for " + 订阅类型, Accept: "*/*" },
                    });
                    if (response.ok) {
                        const 转换后内容 = await response.text();
                        if (订阅类型 === "clash")
                            responseHeaders["content-type"] = "application/x-yaml; charset=utf-8";
                        else if (订阅类型 === "singbox")
                            responseHeaders["content-type"] = "application/json; charset=utf-8";
                        return new Response(转换后内容, { status: 200, headers: responseHeaders });
                    } else {
                        const errorText = await response.text().catch(() => "");
                        return text(
                            "订阅转换失败: " +
                                response.statusText +
                                "\n" +
                                errorText +
                                "\nURL: " +
                                订阅转换URL,
                            500,
                        );
                    }
                } catch {
                    return new Response(b64e(nodesContent) + "\n", {
                        status: 200,
                        headers: responseHeaders,
                    });
                }
            }
        }

        if (url.pathname === "/" || url.pathname === "/index.html") {
            const html = `
<!doctype html>
<html lang="zh-CN">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<title>ZQ-VTPanel</title>
	<link rel="icon" type="image/png" href="https://img.520jacky.dpdns.org/i/2026/04/21/489658.webp">
	<style>
		:root {
		    --primary: #2563eb;
		    --primary-light: #3b82f6;
		    --primary-dark: #1d4ed8;
		    --bg-gradient-start: #eff6ff;
		    --bg-gradient-end: #dbeafe;
		    --card-bg: rgba(255,255,255,0.95);
		    --text-primary: #1e3a5f;
		    --text-secondary: #64748b;
		    --border-color: #bfdbfe;
		    --shadow: 0 4px 6px -1px rgba(37,99,235,0.1),0 2px 4px -1px rgba(37,99,235,0.06);
		    --shadow-lg: 0 20px 25px -5px rgba(37,99,235,0.15),0 10px 10px -5px rgba(37,99,235,0.1);
		}
		* { box-sizing: border-box; }
		body {
		    font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
		    margin: 0;
		    min-height: 100vh;
		    background: linear-gradient(135deg,var(--bg-gradient-start) 0%,var(--bg-gradient-end) 100%);
		    color: var(--text-primary);
		    line-height: 1.6;
		    display: flex;
		    align-items: center;
		    justify-content: center;
		}
		.card {
		    background: var(--card-bg);
		    border-radius: 20px;
		    padding: 32px;
		    box-shadow: var(--shadow-lg);
		    border: 1px solid var(--border-color);
		    max-width: 500px;
		    width: 90%;
		    backdrop-filter: blur(10px);
		}
		h1 {
		    margin: 0 0 24px;
		    font-size: 28px;
		    font-weight: 700;
		    text-align: center;
		    background: linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);
		    -webkit-background-clip: text;
		    -webkit-text-fill-color: transparent;
		    background-clip: text;
		}
		.form-group { margin-bottom: 20px; }
		label {
		    display: block;
		    margin-bottom: 8px;
		    font-weight: 600;
		    color: var(--text-primary);
		}
		input[type="text"] {
		    width: 100%;
		    padding: 14px;
		    border: 2px solid var(--border-color);
		    border-radius: 12px;
		    background: rgba(255,255,255,0.8);
		    color: var(--text-primary);
		    font-size: 16px;
		    box-sizing: border-box;
		    transition: all .3s ease;
		}
		input[type="text"]:focus {
		    outline: none;
		    border-color: var(--primary);
		    box-shadow: 0 0 0 3px rgba(37,99,235,0.1);
		}
		button {
		    width: 100%;
		    background: linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);
		    color: #fff;
		    border: none;
		    border-radius: 12px;
		    padding: 14px;
		    font-size: 16px;
		    font-weight: 600;
		    cursor: pointer;
		    transition: all .3s ease;
		    box-shadow: var(--shadow);
		}
		button:hover {
		    background: linear-gradient(135deg,var(--primary-dark) 0%,var(--primary) 100%);
		    transform: translateY(-2px);
		    box-shadow: var(--shadow-lg);
		}
		.error {
		    margin-top: 16px;
		    color: #dc2626;
		    text-align: center;
		    font-size: 14px;
		    padding: 12px;
		    border-radius: 8px;
		    background: rgba(220,38,38,0.1);
		    border: 1px solid rgba(220,38,38,0.2);
		}
	</style>
</head>
<body>
	<div class="card">
		<h1>ZQ-VTPanel</h1>
		<form method="get">
			<div class="form-group">
				<label for="uuid">请输入UUID</label>
				<input type="text" id="uuid" name="uuid" required placeholder="请输入正确的UUID">
			</div>
			<button type="submit">进入节点界面</button>
		</form>
		<div class="error" id="error" style="display:none">UUID错误，请检查后重新输入</div>
	</div>
	<script>
		document.querySelector('form').addEventListener('submit', function(e) {
		    e.preventDefault();
		    const uuid = document.getElementById('uuid').value.trim();
		    if (!uuid) return;
		    fetch('/' + uuid).then(response => {
		        if (response.ok) {
		            window.location.href = '/' + uuid;
		        } else {
		            const errorDiv = document.getElementById('error');
		            errorDiv.style.display = 'block';
		            errorDiv.textContent = 'UUID错误，请检查后重新输入';
		        }
		    }).catch(() => {
		        const errorDiv = document.getElementById('error');
		        errorDiv.style.display = 'block';
		        errorDiv.textContent = 'UUID错误，请检查后重新输入';
		    });
		});
	</script>
</body>
</html>`;
            return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
        }

        const pathParts = url.pathname.split("/").filter((p) => p);
        if (pathParts.length === 1) {
            const inputUUID = pathParts[0];
            const userConfig = await getUserConfig();
            if (inputUUID !== userConfig.uuid) return new Response("Not Found", { status: 404 });
            const userUUID = userConfig.uuid;
            const origin = new URL(req.url).origin;
            const subUrl = `${origin}/sub/${userUUID}`;
            const lists = getDomainPortLists(req, userConfig);
            const variants = buildVariants(userConfig.s5, userConfig.proxyIp);
            const allNodeUris = [];
            for (const d of lists.domains) {
                for (const p of lists.ports) {
                    for (const v of variants) {
                        const displayName = d.remark ? d.remark : `${v.label} ${d.ip}:${p}`;
                        const trojanDisplayName = d.remark
                            ? `${d.remark}`
                            : `${v.label}  ${d.ip}:${p}`;
                        allNodeUris.push(
                            buildVlessUri(v.raw, userUUID, displayName, lists.workerHost, d.ip, p),
                        );
                        allNodeUris.push(
                            buildTrojanUri(
                                v.raw,
                                userUUID,
                                trojanDisplayName,
                                lists.workerHost,
                                d.ip,
                                p,
                            ),
                        );
                    }
                }
            }
            const allNodesJson = JSON.stringify(allNodeUris);
            const html = `
<!doctype html>
<html lang="zh-CN">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<title>ZQ-VTPanel</title>
	<link rel="icon" type="image/png" href="https://img.520jacky.dpdns.org/i/2026/04/21/489658.webp">
	<style>
		:root {
		  --primary: #2563eb;
		  --primary-light: #3b82f6;
		  --primary-dark: #1d4ed8;
		  --bg-gradient-start: #eff6ff;
		  --bg-gradient-end: #dbeafe;
		  --card-bg: rgba(255, 255, 255, 0.95);
		  --text-primary: #1e3a5f;
		  --text-secondary: #64748b;
		  --border-color: #bfdbfe;
		  --shadow: 0 4px 6px -1px rgba(37, 99, 235, 0.1), 0 2px 4px -1px rgba(37, 99, 235, 0.06);
		  --shadow-lg: 0 20px 25px -5px rgba(37, 99, 235, 0.15), 0 10px 10px -5px rgba(37, 99, 235, 0.1);
		}
		
		* {
		  box-sizing: border-box;
		}
		
		body {
		  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
		  margin: 0;
		  min-height: 100vh;
		  background: linear-gradient(135deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
		  color: var(--text-primary);
		  line-height: 1.6;
		}
		
		.wrap {
		  max-width: 1000px;
		  margin: 0 auto;
		  padding: 32px 24px;
		  position: relative;
		}
		
		.header {
		  text-align: center;
		  margin-bottom: 32px;
		  padding: 24px 0;
		  border-bottom: 2px solid var(--border-color);
		}
		
		h1 {
		  margin: 0;
		  font-size: 32px;
		  font-weight: 700;
		  background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
		  -webkit-background-clip: text;
		  -webkit-text-fill-color: transparent;
		  background-clip: text;
		}
		
		.subtitle {
		  color: var(--text-secondary);
		  margin-top: 8px;
		  font-size: 14px;
		}
		
		.topbar {
		  position: absolute;
		  right: 24px;
		  top: 32px;
		  display: flex;
		  gap: 12px;
		}
		
		.topbar a {
		  width: 42px;
		  height: 42px;
		  border-radius: 12px;
		  background: var(--card-bg);
		  border: 1px solid var(--border-color);
		  color: var(--primary);
		  display: inline-flex;
		  align-items: center;
		  justify-content: center;
		  transition: all .3s ease;
		  box-shadow: var(--shadow);
		}
		
		.topbar a:hover {
		  background: var(--primary);
		  color: #fff;
		  transform: translateY(-2px);
		  box-shadow: var(--shadow-lg);
		}
		
		.main-card {
		  background: var(--card-bg);
		  border-radius: 20px;
		  padding: 28px;
		  margin-bottom: 24px;
		  box-shadow: var(--shadow-lg);
		  border: 1px solid var(--border-color);
		  backdrop-filter: blur(10px);
		}
		
		.section-title {
		  font-size: 18px;
		  font-weight: 600;
		  color: var(--primary);
		  margin-bottom: 16px;
		  display: flex;
		  align-items: center;
		  gap: 8px;
		}
		
		.section-title::before {
		  content: '';
		  width: 4px;
		  height: 20px;
		  background: linear-gradient(180deg, var(--primary) 0%, var(--primary-light) 100%);
		  border-radius: 2px;
		}
		
		.url-box {
		  background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
		  border: 2px solid var(--border-color);
		  border-radius: 12px;
		  padding: 16px;
		  font-family: 'Monaco', 'Consolas', monospace;
		  font-size: 13px;
		  color: var(--text-primary);
		  word-break: break-all;
		  position: relative;
		  overflow: hidden;
		}
		
		.url-box::before {
		  content: '';
		  position: absolute;
		  top: 0;
		  left: 0;
		  right: 0;
		  height: 3px;
		  background: linear-gradient(90deg, var(--primary) 0%, var(--primary-light) 100%);
		}
		
		.button-group {
		  display: flex;
		  gap: 12px;
		  margin-top: 20px;
		  flex-wrap: wrap;
		}
		
		.btn {
		  flex: 1;
		  min-width: 120px;
		  padding: 12px 20px;
		  border-radius: 10px;
		  border: none;
		  font-size: 14px;
		  font-weight: 600;
		  cursor: pointer;
		  transition: all .3s ease;
		  display: inline-flex;
		  align-items: center;
		  justify-content: center;
		  gap: 6px;
		}
		
		.btn-primary {
		  background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
		  color: #fff;
		  box-shadow: 0 4px 14px rgba(37, 99, 235, 0.3);
		}
		
		.btn-primary:hover {
		  transform: translateY(-2px);
		  box-shadow: 0 6px 20px rgba(37, 99, 235, 0.4);
		}
		
		.btn-secondary {
		  background: #fff;
		  color: var(--primary);
		  border: 2px solid var(--border-color);
		}
		
		.btn-secondary:hover {
		  transform: translateY(-2px);
		  box-shadow: var(--shadow-lg);
		}
		
		.btn-success {
		  background: linear-gradient(135deg, #10b981 0%, #34d399 100%);
		  color: #fff;
		  box-shadow: 0 4px 14px rgba(16, 185, 129, 0.3);
		}
		
		.btn-success:hover {
		  transform: translateY(-2px);
		  box-shadow: 0 6px 20px rgba(16, 185, 129, 0.4);
		}
		
		.btn-danger {
		  background: linear-gradient(135deg, #ef4444 0%, #f87171 100%);
		  color: #fff;
		}
		
		.btn-danger:hover {
		  transform: translateY(-2px);
		  box-shadow: 0 6px 20px rgba(239, 68, 68, 0.4);
		}
		
		.form-group {
		  margin-bottom: 20px;
		}
		
		label {
		  display: block;
		  margin-bottom: 8px;
		  font-weight: 600;
		  color: var(--text-primary);
		}
		
		input[type="text"],
		input[type="number"] {
		  width: 100%;
		  padding: 12px 16px;
		  border: 2px solid var(--border-color);
		  border-radius: 10px;
		  background: #fff;
		  color: var(--text-primary);
		  font-size: 14px;
		  box-sizing: border-box;
		  transition: all .3s ease;
		}
		
		input[type="text"]:focus,
		input[type="number"]:focus {
		  outline: none;
		  border-color: var(--primary);
		  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
		}
		
		.input-group {
		  display: flex;
		  gap: 8px;
		}
		
		.input-group input {
		  flex: 1;
		}
		
		.input-group .btn {
		  flex: none;
		  min-width: auto;
		  padding: 10px 16px;
		  font-size: 13px;
		}
		
		.list {
		  display: flex;
		  flex-direction: column;
		  gap: 8px;
		  margin-bottom: 12px;
		}
		
		.list-item {
		  display: flex;
		  gap: 8px;
		  align-items: center;
		}
		
		.list-item input {
		  flex: 1;
		}
		
		.list-item .btn {
		  flex: none;
		  min-width: auto;
		  padding: 8px 12px;
		  font-size: 12px;
		}
		
		.chip {
		  padding: 6px 14px;
		  font-size: 12px;
		  min-width: auto;
		}
		
		.link-arrow {
		  color: var(--primary);
		  text-decoration: none;
		  font-size: 14px;
		  display: inline-flex;
		  align-items: center;
		  justify-content: center;
		  width: 28px;
		  height: 28px;
		  border-radius: 8px;
		  background: var(--bg-gradient-end);
		  transition: all .3s ease;
		  margin-left: 8px;
		}
		
		.link-arrow:hover {
		  background: var(--primary);
		  color: #fff;
		}
		
		.label-with-link {
		  display: flex;
		  align-items: center;
		}
		
		.config-section {
		  display: none;
		}
		
		.config-section.active {
		  display: block;
		}
		
		.collapse-section {
		  margin-bottom: 16px;
		  border: 2px solid var(--border-color);
		  border-radius: 12px;
		  overflow: hidden;
		}
		
		.collapse-header {
		  width: 100%;
		  padding: 16px 20px;
		  background: linear-gradient(135deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
		  border: none;
		  cursor: pointer;
		  display: flex;
		  align-items: center;
		  justify-content: space-between;
		  font-size: 16px;
		  font-weight: 600;
		  color: var(--text-primary);
		  transition: all .3s ease;
		}
		
		.collapse-header:hover {
		  background: linear-gradient(135deg, var(--bg-gradient-end) 0%, var(--bg-gradient-start) 100%);
		}
		
		.collapse-header .icon {
		  font-size: 20px;
		  transition: transform .3s ease;
		}
		
		.collapse-header.active .icon {
		  transform: rotate(180deg);
		}
		
		.collapse-content {
		  max-height: 0;
		  overflow: hidden;
		  transition: max-height .3s ease, padding .3s ease;
		  padding: 0 20px;
		}
		
		.collapse-content.active {
		  max-height: 2000px;
		  padding: 20px;
		}
		
		.qr-modal {
		  display: none;
		  position: fixed;
		  top: 0;
		  left: 0;
		  width: 100%;
		  height: 100%;
		  background: rgba(30, 58, 95, 0.6);
		  backdrop-filter: blur(4px);
		  z-index: 1000;
		  align-items: center;
		  justify-content: center;
		  padding: 20px;
		}
		
		.qr-modal.active {
		  display: flex;
		}
		
		.qr-content {
		  background: var(--card-bg);
		  border-radius: 24px;
		  padding: 32px;
		  text-align: center;
		  max-width: 400px;
		  width: 100%;
		  box-shadow: var(--shadow-lg);
		  border: 1px solid var(--border-color);
		  position: relative;
		}
		
		.qr-content::before {
		  content: '';
		  position: absolute;
		  top: 0;
		  left: 0;
		  right: 0;
		  height: 6px;
		  background: linear-gradient(90deg, var(--primary) 0%, var(--primary-light) 100%);
		  border-radius: 24px 24px 0 0;
		}
		
		.qr-title {
		  font-size: 20px;
		  font-weight: 600;
		  color: var(--text-primary);
		  margin-bottom: 8px;
		}
		
		.qr-subtitle {
		  color: var(--text-secondary);
		  font-size: 14px;
		  margin-bottom: 20px;
		}
		
		#qrCanvas {
		  display: flex;
		  justify-content: center;
		  margin: 20px 0;
		  padding: 20px;
		  background: #fff;
		  border-radius: 16px;
		  border: 2px solid var(--border-color);
		}
		
		.qr-close {
		  background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
		  color: #fff;
		  border: none;
		  padding: 12px 32px;
		  border-radius: 10px;
		  font-weight: 600;
		  cursor: pointer;
		  transition: all .3s ease;
		}
		
		.qr-close:hover {
		  transform: translateY(-2px);
		  box-shadow: 0 4px 14px rgba(37, 99, 235, 0.3);
		}
		
		.toast {
		  position: fixed;
		  bottom: 24px;
		  left: 50%;
		  transform: translateX(-50%) translateY(100px);
		  background: var(--text-primary);
		  color: #fff;
		  padding: 12px 24px;
		  border-radius: 10px;
		  font-size: 14px;
		  opacity: 0;
		  transition: all .3s ease;
		  z-index: 2000;
		}
		
		.toast.show {
		  transform: translateX(-50%) translateY(0);
		  opacity: 1;
		}
		
		.message {
		  margin-top: 12px;
		  padding: 12px 16px;
		  border-radius: 10px;
		  text-align: center;
		  font-size: 14px;
		  font-weight: 500;
		}
		
		.message.success {
		  background: #d1fae5;
		  border: 1px solid #a7f3d0;
		  color: #065f46;
		}
		
		.message.error {
		  background: #fee2e2;
		  border: 1px solid #fecaca;
		  color: #991b1b;
		}
		
		.spinner {
		  display: inline-block;
		  width: 12px;
		  height: 12px;
		  border: 2px solid rgba(255, 255, 255, .35);
		  border-top-color: #fff;
		  border-radius: 50%;
		  animation: spin .8s linear infinite;
		  margin-right: 6px;
		  vertical-align: -2px;
		}
		
		@keyframes spin {
		  to {
		    transform: rotate(360deg);
		  }
		}
		
		@media(max-width: 640px) {
		  .wrap {
		    padding: 16px;
		  }
		
		  h1 {
		    font-size: 24px;
		  }
		
		  .topbar {
		    position: static;
		    justify-content: center;
		    margin-bottom: 20px;
		  }
		
		  .btn {
		    min-width: 100%;
		    margin-bottom: 8px;
		  }
		
		  .tab-nav {
		    overflow-x: auto;
		    flex-wrap: nowrap;
		  }
		
		  .tab-btn {
		    white-space: nowrap;
		  }
	</style>
</head>
<body>
	<div class="wrap">
		<div class="header">
			<h1>✨ZQ-VTPanel</h1>
			<div class="subtitle">安全、快速、稳定的代理服务</div>
		</div>
		<div class="topbar">
			<a class="gh" href="https://github.com/BAYUEQI/ZQ-VTPanel" target="_blank" rel="nofollow noopener" aria-label="GitHub 项目">
				<svg viewBox="0 0 16 16" width="20" height="20" aria-hidden="true" fill="currentColor">
					<path
						d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z">
					</path>
				</svg>
			</a>
		</div>
		<div class="main-card">
			<div class="collapse-section">
				<button class="collapse-header active" data-collapse="sub-content">
					<span>📡订阅链接</span>
					<span class="icon">▼</span>
				</button>
				<div class="collapse-content active" id="sub-content">
					<div class="url-box">${subUrl}</div>
					<div class="button-group">
						<button class="btn btn-primary copy" data-text="${subUrl}">📋复制订阅链接</button>
						<button class="btn btn-secondary copy" id="exportNodes">📤导出节点信息</button>
						<button class="btn btn-success" id="showQrBtn">📱显示二维码</button>
					</div>
				</div>
			</div>
			<div class="collapse-section">
				<button class="collapse-header" data-collapse="config-content">
					<span>⚙️配置管理</span>
					<span class="icon">▼</span>
				</button>
				<div class="collapse-content" id="config-content">
					<form id="configForm">
						<div class="form-group">
							<label for="uuid">UUID</label>
							<input type="text" id="uuid" name="uuid" required placeholder="请输入UUID">
						</div>
						<div class="form-group">
							<div class="label-with-link">
								<label>优选IP(可选)</label>
								<a href="https://ipdb.030101.xyz/bestcfv4/" target="_blank" rel="nofollow noopener" class="link-arrow" title="优选IP地址">↗</a>
							</div>
							<div id="domains" class="list"></div>
							<div class="input-group">
								<input type="text" id="domainNew" placeholder="输入IP">
								<input type="text" id="domainRemarkNew" placeholder="输入备注（可选）">
								<button type="button" id="addDomain" class="btn btn-secondary chip">➕添加</button>
							</div>
						</div>
						<div class="form-group">
							<label>端口(可选)</label>
							<div id="ports" class="list"></div>
							<div class="input-group">
								<input type="number" id="portNew" min="1" max="65535" placeholder="输入端口后点击添加">
								<button type="button" id="addPort" class="btn btn-secondary chip">➕添加</button>
							</div>
						</div>
						<div class="form-group">
							<label for="s5">SOCKS5代理(可选)</label>
							<div class="input-group">
								<input type="text" id="s5" name="s5" placeholder="格式: user:pass@host:port 或 host:port">
							</div>
						</div>
						<div class="form-group">
							<div class="label-with-link">
								<label for="proxyIp">ProxyIP(可选)</label>
								<a href="https://ipdb.030101.xyz/bestproxy/" target="_blank" rel="nofollow noopener" class="link-arrow" title="ProxyIP地址">↗</a>
							</div>
							<div class="input-group">
								<input type="text" id="proxyIp" name="proxyIp" placeholder="格式: host:port 或 host">
							</div>
						</div>
						<div class="form-group">
							<label for="fallbackTimeout">回退检测时间(可选)</label>
							<div class="input-group">
								<input type="number" id="fallbackTimeout" name="fallbackTimeout" min="1" max="5000" placeholder="默认100毫秒">
							</div>
						</div>
						<div class="button-group">
							<button type="submit" class="btn btn-primary">💾保存配置</button>
							<button type="button" class="btn btn-secondary" id="reloadBtn">🔄重新加载</button>
						</div>
						<div id="message" class="message" style="display:none"></div>
					</form>
				</div>
			</div>
		</div>
		<div class="qr-modal" id="qrModal">
			<div class="qr-content">
				<div class="qr-title">📱扫码订阅</div>
				<div class="qr-subtitle">使用客户端扫描二维码快速添加</div>
				<div id="qrCanvas"></div>
				<button class="qr-close" id="closeQrBtn">关闭</button>
			</div>
		</div>
		<div class="toast" id="toast"></div>
		<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
		<script>
			(function() {
			    const toastEl = document.getElementById('toast');
			
			    function showToast(msg) {
			        toastEl.textContent = msg;
			        toastEl.classList.add('show');
			        setTimeout(() => toastEl.classList.remove('show'), 2000);
			    }
			
			    function showMessage(text, type) {
			        const el = document.getElementById('message');
			        el.textContent = text;
			        el.className = 'message ' + type;
			        el.style.display = 'block';
			        setTimeout(() => {
			            el.style.display = 'none';
			        }, 3000);
			    }
			
			    function fallbackCopy(text) {
			        const ta = document.createElement('textarea');
			        ta.value = text;
			        ta.setAttribute('readonly', '');
			        ta.style.position = 'absolute';
			        ta.style.left = '-9999px';
			        document.body.appendChild(ta);
			        ta.select();
			        let ok = false;
			        try {
			            ok = document.execCommand('copy');
			        } catch (e) {}
			        document.body.removeChild(ta);
			        return ok;
			    }
			
			    async function doCopy(btn) {
			        const t = btn.getAttribute('data-text');
			        if (!t) return;
			        let ok = false;
			        
			        if (navigator.clipboard && navigator.clipboard.writeText) {
			            try {
			                await navigator.clipboard.writeText(t);
			                ok = true;
			            } catch (e) {
			                ok = false;
			            }
			        }
			        
			        if (!ok) {
			            ok = fallbackCopy(t);
			        }
			        
			        showToast(ok ? '✅ 已复制到剪贴板' : '❌ 复制失败');
			    }
			
			    document.querySelectorAll('button.copy').forEach(b => 
			        b.addEventListener('click', e => {
			            doCopy(e.currentTarget);
			        })
			    );
			
			    const exportBtn = document.getElementById('exportNodes');
			    if (exportBtn) {
			        exportBtn.addEventListener('click', async () => {
			            const allNodes = ${allNodesJson};
			            const nodeText = allNodes.join('\\n') + '\\n';
			            const nodeTextBase64 = btoa(unescape(encodeURIComponent(nodeText)));
			            let ok = false;
			            
			            if (navigator.clipboard && navigator.clipboard.writeText) {
			                try {
			                    await navigator.clipboard.writeText(nodeTextBase64);
			                    ok = true;
			                } catch (e) {
			                    ok = false;
			                }
			            }
			            
			            if (!ok) {
			                ok = fallbackCopy(nodeTextBase64);
			            }
			            
			            showToast(ok ? '✅ 已导出到剪贴板' : '❌ 导出失败');
			        });
			    }
			
			    const showQrBtn = document.getElementById('showQrBtn');
			    const qrModal = document.getElementById('qrModal');
			    const closeQrBtn = document.getElementById('closeQrBtn');
			    const qrCanvas = document.getElementById('qrCanvas');
			    let qrCode = null;
			
			    showQrBtn.addEventListener('click', () => {
			        qrModal.classList.add('active');
			        if (!qrCode) {
			            qrCode = new QRCode(qrCanvas, {
			                text: '${subUrl}',
			                width: 220,
			                height: 220,
			                colorDark: '#2563eb',
			                colorLight: '#ffffff',
			                correctLevel: QRCode.CorrectLevel.M
			            });
			        }
			    });
			
			    closeQrBtn.addEventListener('click', () => {
			        qrModal.classList.remove('active');
			    });
			
			    qrModal.addEventListener('click', (e) => {
			        if (e.target === qrModal) qrModal.classList.remove('active');
			    });
			
			    const tabBtns = document.querySelectorAll('.tab-btn');
			    const configSections = document.querySelectorAll('.config-section');
			
			    tabBtns.forEach(btn => {
			        btn.addEventListener('click', () => {
			            const tab = btn.dataset.tab;
			            tabBtns.forEach(b => b.classList.remove('active'));
			            configSections.forEach(s => s.classList.remove('active'));
			            btn.classList.add('active');
			            document.getElementById(tab + '-section').classList.add('active');
			        });
			    });
			
			    function renderList(container, values, placeholder, isPort) {
			        container.innerHTML = '';
			        values.forEach((val, idx) => {
			            const row = document.createElement('div');
			            row.className = 'list-item';
			            
			            if (isPort) {
			                const input = document.createElement('input');
			                input.type = 'number';
			                input.min = '1';
			                input.max = '65535';
			                input.value = String(val);
			                input.placeholder = placeholder;
			                
			                const del = document.createElement('button');
			                del.type = 'button';
			                del.className = 'btn btn-danger chip';
			                del.textContent = '🗑️ 删除';
			                del.addEventListener('click', () => {
			                    values.splice(idx, 1);
			                    renderList(container, values, placeholder, isPort);
			                });
			                
			                row.appendChild(input);
			                row.appendChild(del);
			                container.appendChild(row);
			                
			                input.addEventListener('input', () => {
			                    values[idx] = Number(Math.max(1, Math.min(65535, parseInt(input.value || '0', 10))));
			                });
			            } else {
			                const ipInput = document.createElement('input');
			                ipInput.type = 'text';
			                ipInput.value = val.ip || '';
			                ipInput.placeholder = 'IP地址';
			                ipInput.style.flex = '1';
			                
			                const remarkInput = document.createElement('input');
			                remarkInput.type = 'text';
			                remarkInput.value = val.remark || '';
			                remarkInput.placeholder = '备注（可选）';
			                remarkInput.style.flex = '1';
			                
			                const del = document.createElement('button');
			                del.type = 'button';
			                del.className = 'btn btn-danger chip';
			                del.textContent = '🗑️ 删除';
			                del.addEventListener('click', () => {
			                    values.splice(idx, 1);
			                    renderList(container, values, placeholder, isPort);
			                });
			                
			                row.appendChild(ipInput);
			                row.appendChild(remarkInput);
			                row.appendChild(del);
			                container.appendChild(row);
			                
			                ipInput.addEventListener('input', () => {
			                    values[idx].ip = ipInput.value.trim();
			                });
			                
			                remarkInput.addEventListener('input', () => {
			                    values[idx].remark = remarkInput.value.trim();
			                });
			            }
			        });
			    }
			
			    const state = { domains: [], ports: [] };
			
			    async function loadConfig() {
			        try {
			            const uuid = document.getElementById('uuid').value.trim() || '${userUUID}';
			            const response = await fetch('/api/config/' + uuid);
			            if (!response.ok) throw 0;
			            
			            const cfg = await response.json();
			            document.getElementById('uuid').value = cfg.uuid || '';
			            document.getElementById('s5').value = cfg.s5 || '';
			            document.getElementById('proxyIp').value = cfg.proxyIp || '';
			            document.getElementById('fallbackTimeout').value = cfg.fallbackTimeout || 100;
			            
			            if (Array.isArray(cfg.domains)) {
			                state.domains = cfg.domains.map(item => {
			                    if (typeof item === 'string') {
			                        return { ip: item, remark: '' };
			                    }
			                    return item;
			                });
			            } else {
			                state.domains = [];
			            }
			            
			            if ((cfg.domain || '').trim() && !state.domains.some(x => x.ip === cfg.domain.trim())) {
			                state.domains.unshift({ ip: cfg.domain.trim(), remark: '' });
			            }
			            
			            state.ports = (Array.isArray(cfg.ports) ? cfg.ports : [])
			                .map(x => parseInt(x, 10))
			                .filter(n => n > 0 && n <= 65535);
			            
			            if (parseInt(cfg.port, 10)) state.ports.unshift(parseInt(cfg.port, 10));
			            
			            state.ports = [...new Set(state.ports)];
			            
			            renderList(document.getElementById('domains'), state.domains, '', false);
			            renderList(document.getElementById('ports'), state.ports, '如: 443', true);
			            
			            showMessage('✅ 配置加载成功', 'success');
			        } catch (e) {
			            showMessage('❌ 配置加载失败', 'error');
			        }
			    }
			
			    async function saveConfigForm() {
			        const uuid = document.getElementById('uuid').value.trim();
			        const s5 = document.getElementById('s5').value.trim();
			        const proxyIp = document.getElementById('proxyIp').value.trim();
			        const fallbackTimeout = parseInt(document.getElementById('fallbackTimeout').value, 10) || 100;
			        
			        const domainItems = Array.from(document.querySelectorAll('#domains .list-item'));
			        const domains = [];
			        domainItems.forEach(row => {
			            const inputs = row.querySelectorAll('input');
			            if (inputs.length >= 2) {
			                const ip = inputs[0].value.trim();
			                const remark = inputs[1].value.trim();
			                if (ip) domains.push({ ip, remark });
			            }
			        });
			        
			        const ports = Array.from(document.querySelectorAll('#ports .list-item input'))
			            .map(i => parseInt(i.value, 10))
			            .filter(n => n > 0 && n <= 65535);
			        
			        const body = { uuid, s5, proxyIp, domains, ports, fallbackTimeout };
			        
			        const response = await fetch('/api/config/' + uuid, {
			            method: 'POST',
			            headers: { 'content-type': 'application/json' },
			            body: JSON.stringify(body)
			        });
			        
			        const result = await response.json();
			        
			        if (response.ok) {
			            showMessage('✅ ' + (result.message || '配置保存成功'), 'success');
			            setTimeout(() => {
			                window.location.href = '/' + uuid;
			            }, 800);
			        } else {
			            showMessage('❌ ' + (result.error || '配置保存失败'), 'error');
			        }
			    }
			
			    document.addEventListener('DOMContentLoaded', () => {
			        const collapseHeaders = document.querySelectorAll('.collapse-header');
			        collapseHeaders.forEach(header => {
			            header.addEventListener('click', () => {
			                const targetId = header.getAttribute('data-collapse');
			                const content = document.getElementById(targetId);
			                const isActive = header.classList.contains('active');
			                
			                if (isActive) {
			                    header.classList.remove('active');
			                    content.classList.remove('active');
			                } else {
			                    header.classList.add('active');
			                    content.classList.add('active');
			                }
			            });
			        });
			        
			        const addDomain = document.getElementById('addDomain');
			        const addPort = document.getElementById('addPort');
			        const domainNew = document.getElementById('domainNew');
			        const domainRemarkNew = document.getElementById('domainRemarkNew');
			        const portNew = document.getElementById('portNew');
			        const reloadBtn = document.getElementById('reloadBtn');
			        
			        addDomain && addDomain.addEventListener('click', () => {
			            const v = (domainNew.value || '').trim();
			            const r = (domainRemarkNew.value || '').trim();
			            if (!v) return;
			            state.domains.push({ ip: v, remark: r });
			            renderList(document.getElementById('domains'), state.domains, '', false);
			            domainNew.value = '';
			            domainRemarkNew.value = '';
			        });
			        
			        addPort && addPort.addEventListener('click', () => {
			            const n = parseInt(portNew.value || '0', 10);
			            if (!n || n < 1 || n > 65535) return;
			            state.ports.push(n);
			            renderList(document.getElementById('ports'), state.ports, '如: 443', true);
			            portNew.value = '';
			        });
			        
			        reloadBtn && reloadBtn.addEventListener('click', () => {
			            loadConfig();
			        });
			    });
			
			    document.getElementById('configForm').addEventListener('submit', function(e) {
			        e.preventDefault();
			        saveConfigForm();
			    });
			
			    loadConfig();
			})();
		</script>
</body>
</html>`;
            return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
        }
        return new Response("Not Found", { status: 404 });
    },
};
