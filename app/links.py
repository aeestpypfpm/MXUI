"""URI builders for VLESS/Trojan over WebSocket and XHTTP across TLS/HTTP/CDN regions."""
from __future__ import annotations

from urllib.parse import quote

from app.state import CONFIG, DEFAULT_FINGERPRINT, DEFAULT_PROTOCOL, parse_protocol


def generate_proxy_link(
    uuid: str,
    host: str,
    remark: str = "MX-UI",
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str | None = None,
    alpn: str | None = None,
    connect_address: str | None = None,
    connect_port: int | None = None,
    scheme: str = "https",
    sni_override: str | None = None,
    cdn_host: str | None = None,
) -> str:
    family, transport, mode = parse_protocol(protocol)
    fp = (fingerprint or DEFAULT_FINGERPRINT).strip()
    alpn_val = (alpn or ("h2,http/1.1" if transport == "xhttp" else "http/1.1")).strip()

    use_tls = scheme == "https"
    port_val = connect_port or (443 if use_tls else 80)
    ws_host = (cdn_host or CONFIG.get("cdn_host") or host).strip()
    sni_val = (sni_override or ws_host).strip()
    address = (connect_address or ws_host).strip()

    if family == "trojan":
        path = "/xhttp-trojan" if transport == "xhttp" else "/ws-trojan"
    else:
        path = "/xhttp" if transport == "xhttp" else "/ws"

    params: dict[str, str] = {
        "security": "tls" if use_tls else "none",
        "type": transport,
        "host": ws_host,
        "path": path,
    }
    if use_tls:
        params["sni"] = sni_val
        params["fp"] = fp
        if alpn_val:
            params["alpn"] = alpn_val

    if transport == "xhttp" and mode:
        params["mode"] = mode

    if family == "vless":
        params["encryption"] = "none"

    query = "&".join(f"{k}={quote(str(v), safe=',/:')}" for k, v in params.items())
    return f"{family}://{uuid}@{address}:{port_val}?{query}#{quote(remark)}"


def primary_link_for_config(
    link: dict,
    uid: str,
    host: str,
    connect_port: int = 443,
    scheme: str = "https",
) -> str:
    return generate_proxy_link(
        uuid=uid,
        host=host,
        remark=f"MX-UI-{link.get('label', 'Config')}",
        protocol=link.get("protocol", DEFAULT_PROTOCOL),
        fingerprint=link.get("fingerprint"),
        alpn=link.get("alpn"),
        connect_port=connect_port,
        scheme=scheme,
        sni_override=link.get("sni") or None,
        cdn_host=link.get("cdn_host") or None,
    )


def build_all_proxy_links(
    link: dict,
    uid: str,
    host: str,
    connect_port: int = 443,
    scheme: str = "https",
) -> list[str]:
    proto = link.get("protocol", DEFAULT_PROTOCOL)
    fp = link.get("fingerprint")
    alpn = link.get("alpn")
    sni = link.get("sni") or None
    cdn_host = link.get("cdn_host") or None
    base_remark = f"MX-UI-{link.get('label', 'Config')}"

    out = [
        generate_proxy_link(
            uuid=uid,
            host=host,
            remark=f"{base_remark} (Primary)",
            protocol=proto,
            fingerprint=fp,
            alpn=alpn,
            connect_port=connect_port,
            scheme=scheme,
            sni_override=sni,
            cdn_host=cdn_host,
        )
    ]
    for i, entry in enumerate(link.get("ip_pool") or [], start=1):
        ip = entry.get("ip")
        port = int(entry.get("port") or connect_port or 443)
        if ip:
            out.append(
                generate_proxy_link(
                    uuid=uid,
                    host=host,
                    remark=f"{base_remark} (Edge {i})",
                    protocol=proto,
                    fingerprint=fp,
                    alpn=alpn,
                    connect_address=ip,
                    connect_port=port,
                    scheme=scheme,
                    sni_override=sni,
                    cdn_host=cdn_host,
                )
            )
    return out
