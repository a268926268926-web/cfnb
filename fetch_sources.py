# -*- coding: utf-8 -*-
"""
fetch_sources.py — 多源聚合优选池（全自动，产出 30 个）
所有源都是"活"的：各源随上游作者/频道实时更新，本脚本每次运行时重新拉取最新数据。

源清单（6 个活源，按优先级配额）：
  S1 zip.cm.edu.kg/all.json        CM 全量库（15176 条，含 colo 落地字段）→ 精筛 NRT/JP/TW
  S2 ip.v2too.top/api/nodes        亦心の优选IP 官方接口（江西电信 500M 实测，carrier=ct 电信条目）
  S3 t.me/s/danfeng2               丹枫频道（每 6h 一条精品 NRT 元数据帖，解析 HTML 拿 IP:端口）
  S4 t.me/s/cfyxip                 亦心频道网页预览（每小时电信/移动榜单，解析 code 块 IP）
  S5 LancelotRar/best-cf-ips       GitHub 聚合库（多源聚合去重+国家标注，每 3h 扫描 top100）
  S6 joname1/BestCFip              GitHub 聚合库（每 4h 构建，聚合 7 个上游源）
  备用: addressesapi.090227.xyz/ct|cmcc（CM 分 ISP 小库）、svip-s/cloudflare_ip（每小时，陕西移动视角）

产出: zip_nrt.txt（30 个，IP:port#国家码 格式，cfnb ADDITIONAL_SOURCES file:// 源）
"""
import json, io, os, re, urllib.request

DIR = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(DIR, "zip_nrt.txt")
TARGET = 30
TIMEOUT = 60
UA = {"User-Agent": "Mozilla/5.0 cfnb-sources/2.0"}

def http_get(url, timeout=TIMEOUT):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")

# ---------- 各源解析函数，返回 [(ip, port, 国家码, 来源标签)] ----------

def src_zip():  # S1: CM 全量库 → NRT 落地 / JP / TW
    data = json.loads(http_get("https://zip.cm.edu.kg/all.json"))
    items = data.get("data", [])
    nrt, jp, tw = [], [], []
    for it in items:
        ip = it.get("ip"); ports = it.get("port") or []
        meta = it.get("meta") or {}
        colo = (meta.get("colo") or {}).get("iata", "")
        cc = meta.get("country", "")
        port = 443 if 443 in ports else (ports[0] if ports else None)
        if not ip or not port:
            continue
        rec = (ip, port, cc or "XX")
        if colo == "NRT":
            nrt.append(rec)
        elif cc == "JP":
            jp.append(rec)
        elif cc == "TW":
            tw.append(rec)
    out = []
    quota = {"nrt": 10, "jp": 4, "tw": 4}   # 18 个
    seen = set()
    def take(pool, n):
        got = 0
        for ip, port, cc in pool:
            if got >= n: break
            if ip in seen: continue
            seen.add(ip); out.append((ip, port, cc, "CMzip")); got += 1
    take(nrt, quota["nrt"]); take(jp, quota["jp"]); take(tw, quota["tw"])
    if len(out) < 18:
        take(nrt, 18)
    print(f"[S1 CMzip] {len(out)} 个（NRT库{len(nrt)}/JP库{len(jp)}/TW库{len(tw)}）")
    return out

def src_v2too():  # S2: 亦心官方接口，只取电信(ct)条目，按速度排序
    try:
        arr = json.loads(http_get("https://ip.v2too.top/api/nodes", timeout=20))
        ct = [x for x in arr if x.get("carrier") == "ct" and x.get("speed", 0) > 0.05]
        ct.sort(key=lambda x: -x.get("speed", 0))
        # 国家码用落地 region 映射（SIN→SG 等），保证两位 ISO 码可解析
        region_map = {"SIN": "SG", "HKG": "HK", "NRT": "JP", "LAX": "US", "SJC": "US"}
        out = [(x["ip"], 443, region_map.get(x.get("region", ""), "SG"), "v2too") for x in ct[:6]]
        print(f"[S2 v2too] {len(out)} 个（电信条目总数 {len(ct)}）")
        return out
    except Exception as e:
        print(f"[S2 v2too] 失败: {e}")
        return []

def src_tg_text(url, max_ips):  # S3/S4 通用：t.me/s 网页预览解析
    try:
        raw = http_get(url, timeout=25)
        blocks = re.findall(r'tgme_widget_message_text[^>]*>(.*?)</div>', raw, re.S)
        ips = []
        for b in blocks:  # 时间序：页面从旧到新，取最新的块优先
            text = re.sub(r'<[^>]+>', ' ', b)
            text = re.sub(r'█+', ' ', text)
            for m in re.finditer(r'\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{2,5}))?\b', text):
                ip = m.group(1)
                if ip not in [p[0] for p in ips]:
                    ips.append((ip, int(m.group(2)) if m.group(2) else 443, "CF", url.split('/')[-1]))
            if len(ips) >= max_ips:
                break
        print(f"[{url.split('/')[-1]}] {len(ips[:max_ips])} 个")
        return ips[:max_ips]
    except Exception as e:
        print(f"[{url.split('/')[-1]}] 失败: {e}")
        return []

def src_lancelot():  # S5: best-cf-ips top100（昨天扫描，聚合+标注）
    try:
        raw = http_get("https://raw.githubusercontent.com/LancelotRar/best-cf-ips/main/best-cf-ip-scanned-top100.txt", timeout=20)
        out = []
        for line in raw.splitlines():
            m = re.match(r'(\d+\.\d+\.\d+\.\d+):(\d+)#([A-Z]{2})', line.strip())
            if m:
                out.append((m.group(1), int(m.group(2)), m.group(3), "Lancelot"))
        print(f"[S5 Lancelot] {len(out[:5])} 个（源总数 {len(out)}）")
        return out[:5]
    except Exception as e:
        print(f"[S5 Lancelot] 失败: {e}")
        return []

def src_joname1():  # S6: BestCFip ipv4.txt（4h 构建，聚合 7 源）
    try:
        raw = http_get("https://raw.githubusercontent.com/joname1/BestCFip/refs/heads/main/ipv4.txt", timeout=20)
        out = []
        for line in raw.splitlines():
            m = re.match(r'(\d+\.\d+\.\d+\.\d+):(\d+)#([A-Z]{2})', line.strip())
            if m:
                out.append((m.group(1), int(m.group(2)), m.group(3), "BestCFip"))
        print(f"[S6 BestCFip] {len(out[:5])} 个（源总数 {len(out)}）")
        return out[:5]
    except Exception as e:
        print(f"[S6 BestCFip] 失败: {e}")
        return []

def main():
    pool, seen = [], set()
    sources = [
        ("S1 CMzip", src_zip),
        ("S2 v2too", src_v2too),
        ("S3 danfeng2", lambda: src_tg_text("https://t.me/s/danfeng2", 4)),
        ("S4 cfyxip", lambda: src_tg_text("https://t.me/s/cfyxip", 4)),
        ("S5 Lancelot", src_lancelot),
        ("S6 BestCFip", src_joname1),
    ]
    for name, fn in sources:
        try:
            items = fn()
        except Exception as e:
            print(f"[{name}] 异常: {e}"); items = []
        for ip, port, cc, tag in items:
            if ip in seen:
                continue
            seen.add(ip)
            pool.append((ip, port, cc, tag))

    print(f"\n聚合后唯一 IP 总数: {len(pool)}")

    # 国家码兜底：非标准码统一为 "CF"
    lines = []
    for ip, port, cc, tag in pool[:TARGET]:
        cc = cc if re.match(r'^[A-Z]{2}$', cc or "") else "CF"
        lines.append(f"{ip}:{port}#{cc}")

    # 数量不足则补告警（30 个目标）
    if len(lines) < TARGET:
        print(f"[warn] 仅产出 {len(lines)}/{TARGET}，源质量波动属正常，下次运行自动补齐")
    with io.open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n[done] 产出 {len(lines)} 个 → {OUT}")
    for l in lines:
        print("  ", l)

if __name__ == "__main__":
    main()
