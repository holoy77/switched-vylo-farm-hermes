#!/usr/bin/env python3
import json
import os
import sys
import urllib.parse

def parse_proxy_to_singbox(proxy_str: str) -> dict:
    proxy_str = proxy_str.strip()
    if not proxy_str:
        raise ValueError("Proxy configuration string is empty")

    # 如果直接输入了完整的 sing-box JSON 配置
    if proxy_str.startswith("{"):
        return json.loads(proxy_str)

    parsed = urllib.parse.urlparse(proxy_str)
    scheme = parsed.scheme.lower()
    query = urllib.parse.parse_qs(parsed.query)

    host = parsed.hostname
    port = parsed.port or (443 if scheme in ("hysteria2", "hy2", "https") else 1080)
    outbound = {}

    # 1. Hysteria2 协议解析
    if scheme in ("hysteria2", "hy2"):
        auth = parsed.username or parsed.password or parsed.netloc.split("@")[0]
        sni = query.get("sni", [host])[0]
        insecure = query.get("insecure", ["0"])[0] in ("1", "true", "True")
        outbound = {
            "type": "hysteria2",
            "tag": "proxy-out",
            "server": host,
            "server_port": port,
            "password": auth,
            "tls": {
                "enabled": True,
                "server_name": sni,
                "insecure": insecure
            }
        }

    # 2. SOCKS5 协议解析 (支持带用户名/密码)
    elif scheme in ("socks5", "socks"):
        outbound = {
            "type": "socks",
            "tag": "proxy-out",
            "server": host,
            "server_port": port
        }
        if parsed.username:
            outbound["username"] = urllib.parse.unquote(parsed.username)
        if parsed.password:
            outbound["password"] = urllib.parse.unquote(parsed.password)

    # 3. VLESS 协议解析
    elif scheme == "vless":
        uuid = parsed.username
        sni = query.get("sni", [host])[0]
        insecure = query.get("security", [""])[0] == "tls"
        outbound = {
            "type": "vless",
            "tag": "proxy-out",
            "server": host,
            "server_port": port,
            "uuid": uuid,
            "tls": {
                "enabled": True,
                "server_name": sni
            }
        }
        net_type = query.get("type", ["tcp"])[0]
        if net_type == "ws":
            outbound["transport"] = {
                "type": "ws",
                "path": query.get("path", ["/"])[0]
            }

    # 4. HTTP / HTTPS 协议解析
    elif scheme in ("http", "https"):
        outbound = {
            "type": "http",
            "tag": "proxy-out",
            "server": host,
            "server_port": port
        }
        if parsed.username:
            outbound["username"] = urllib.parse.unquote(parsed.username)
        if parsed.password:
            outbound["password"] = urllib.parse.unquote(parsed.password)
        if scheme == "https":
            outbound["tls"] = {"enabled": True}

    else:
        raise ValueError(f"Unsupported proxy scheme: {scheme}")

    # 生成 sing-box 本地 10900 mixed (SOCKS5/HTTP) 转发配置
    return {
        "log": {
            "level": "warn"
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 10900
            }
        ],
        "outbounds": [
            outbound,
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "rules": [
                {
                    "inbound": "mixed-in",
                    "outbound": "proxy-out"
                }
            ]
        }
    }

def main():
    proxy_val = ""
    if len(sys.argv) > 1 and sys.argv[1].strip():
        proxy_val = sys.argv[1].strip()
    else:
        # 兼容回退读取主流 Secrets 变量名
        for key in ("PROXY_URL", "SECRET_PROXY", "JP_SOCKS_URL", "HOME_VLESS_URL"):
            if os.environ.get(key):
                proxy_val = os.environ[key].strip()
                break

    if not proxy_val:
        print("[make_relay] 未提供代理节点，将直接直连，不生成 sing-box 配置。")
        sys.exit(0)

    try:
        config = parse_proxy_to_singbox(proxy_val)
        with open("sing-box-config.json", "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        print("[make_relay] 成功根据节点生成 sing-box 配置文件: sing-box-config.json (监听 127.0.0.1:10900)")
    except Exception as e:
        print(f"[make_relay] 解析节点生成配置失败: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
