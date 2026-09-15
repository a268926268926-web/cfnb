# -*- coding: utf-8 -*-
"""
fetch_sources.py — 多源聚合筛选器（全自动，产出 30 个候选池）

职责定位（2026-09-15 按用户口径修订）：
  聚合器只做三件"过滤"的事——去掉不要的地区、去掉不要的端口、去掉重复 IP。
  **不做质量裁决**：质量由下游 cfnb 实测（TCP→可用性→带宽）决定，实测才是唯一真东西。

源清单（活源，各自随上游实时更新）：
  S1 zip.cm.edu.kg/all.json        CM 全量库（含 colo 落地字段；注：其 IP 为反代入口性质，实测可用）
  S2 ip.v2too.top/api/nodes        亦心の优选IP 官方接口（江西电信 500M 实测，carrier=ct）
  S3 t.me/s/danfeng2               丹枫频道（每 6h 精品 NRT 帖）
  S4 t.me/s/cfyxip                 亦心频道网页预览（每小时电信/移动榜单）
  S5 LancelotRar/best-cf-ips       聚合库（3h 扫描 top100）
  S6 joname1/BestCFip             聚合库（4h 构建，7 上游）
  S7 addressesapi.090227.xyz/ct    CM 分 ISP 库（电信专属，小但精准）
  S8 svip-s/cloudflare_ip         每小时更新（陕西移动视角）

筛选规则：
  地区白名单（含配额）：NRT 10 / JP 4 / TW 4 / SG 6 / US 6
  端口优先级：443 > 2087 > 2053/2083/2096/8443
  去重：同 IP 只留一条，保留其最优端口
  产出：zip_nrt.txt（30 个，IP:port#国家码）
"""
import ipaddress, json, io, os, re, urllib.request

DIR = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(DIR, "zip_nrt.txt")
TIMEOUT = 60
UA = {"User-Agent": "Mozilla/5.0 cfnb-sources/3.0"}

# ---------- 筛选规则 ----------
# 冗余设计：cfnb 实测会淘汰一部分，故候选池按 3 倍供给（90 → 实测取前 30）
REGION_QUOTA = {"NRT": 30, "JP": 12, "TW": 12, "SG": 18, "US": 18}   # 合计 90
PORT_QUOTA = {443: 60, 2087: 12, 2053: 6, 2083: 6, 2096: 3, 8443: 3}  # 端口配额 x3（群实测优先级：443>2087>其余 TLS）
PORT_ORDER = [443, 2087, 2053, 2083, 2096, 8443]                  # 群实测：443 被 Q 最少，2087 次之
ALLOWED_PORTS = set(PORT_ORDER)

def http_get(url, timeout=TIMEOUT):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")

# 落地区域归一：把各种来源的地区标识统一成 NRT/JP/TW/SG/US（其余丢弃）
REGION_ALIAS = {
    "NRT": "NRT", "JP": "JP", "JPN": "JP", "JAPAN": "JP", "TOKYO": "JP", "OSAKA": "JP",
    "TW": "TW", "TWN": "TW", "TAIWAN": "TW", "TPE": "TW", "TAIPEI": "TW",
    "SG": "SG", "SGP": "SG", "SIN": "SG", "SINGAPORE": "SG",
    "US": "US", "USA": "US", "LAX": "US", "SJC": "US", "SEA": "US", "SFO": "US",
}
def norm_region(raw):
    return REGION_ALIAS.get((raw or "").strip().upper(), None)

def pick_port(ports):
    """从候选端口列表里按 PORT_ORDER 优先级挑一个；都不在白名单则返回 None"""
    for p in PORT_ORDER:
        if p in ports:
            return p
    return None

# ---------- 各源解析：统一返回 [(ip, [ports...], 地区标识原始值, 来源标签)] ----------

def src_zip():
    data = json.loads(http_get("https://zip.cm.edu.kg/all.json"))
    out = []
    for it in data.get("data", []):
        ip = it.get("ip"); ports = it.get("port") or []
        meta = it.get("meta") or {}
        colo = (meta.get("colo") or {}).get("iata", "")
        cc = meta.get("country", "")
        region = colo if colo else cc          # 优先用落地机房（NRT/TPE/SIN...），否则原生国家
        out.append((ip, ports, region, "CMzip"))
    print(f"[S1 CMzip] 候选 {len(out)}")
    return out

def src_v2too():
    try:
        arr = json.loads(http_get("https://ip.v2too.top/api/nodes", timeout=20))
        ct = [x for x in arr if x.get("carrier") == "ct" and x.get("speed", 0) > 0.05]
        ct.sort(key=lambda x: -x.get("speed", 0))
        out = [(x["ip"], [443], x.get("region", ""), "v2too") for x in ct]
        print(f"[S2 v2too] 候选 {len(out)}")
        return out
    except Exception as e:
        print(f"[S2 v2too] 失败: {e}")
        return []

def src_tg_text(url, tag):
    raw = None
    for attempt in range(1, 3):
        try:
            raw = http_get(url, timeout=25)
            break
        except Exception as e:
            print(f"[{tag}] 第{attempt}次失败: {e}")
    if raw is None:
        return []
    try:
        blocks = re.findall(r'tgme_widget_message_text[^>]*>(.*?)</div>', raw, re.S)
        out, seen = [], set()
        for b in reversed(blocks):                 # 倒序 = 最新帖优先
            text = re.sub(r'<[^>]+>', ' ', b)
            text = re.sub(r'█+', ' ', text)
            # 帖子里"地区"信息（香港/新加坡/日本…）
            region_hint = ""
            for kw, code in (("日本", "NRT"), ("东京", "NRT"), ("新加坡", "SG"), ("台湾", "TW"),
                             ("香港", "HK"), ("美国", "US"), ("洛杉矶", "US")):
                if kw in text:
                    region_hint = code; break
            for m in re.finditer(r'\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{2,5}))?\b', text):
                ip = m.group(1)
                if ip in seen:
                    continue
                seen.add(ip)
                out.append((ip, [int(m.group(2)) if m.group(2) else 443], region_hint, tag))
        print(f"[{tag}] 候选 {len(out)}")
        return out
    except Exception as e:
        print(f"[{tag}] 失败: {e}")
        return []

def _parse_plain_lines(url, tag):
    try:
        raw = http_get(url, timeout=20)
        out = []
        for line in raw.splitlines():
            line = line.strip()
            m = re.match(r'(\d+\.\d+\.\d+\.\d+)(?::(\d+))?(?:#([A-Za-z]{2,10}))?', line)
            if m:
                out.append((m.group(1), [int(m.group(2))] if m.group(2) else [443],
                            m.group(3) or "", tag))
        print(f"[{tag}] 候选 {len(out)}")
        return out
    except Exception as e:
        print(f"[{tag}] 失败: {e}")
        return []

def src_lancelot():
    return _parse_plain_lines(
        "https://raw.githubusercontent.com/LancelotRar/best-cf-ips/main/best-cf-ip-scanned-top100.txt", "Lancelot")

def src_joname1():
    return _parse_plain_lines(
        "https://raw.githubusercontent.com/joname1/BestCFip/refs/heads/main/ipv4.txt", "BestCFip")

def src_addressesapi():
    out = []
    for path, tag in (("ct", "CM-ct"), ("cmcc", "CM-cmcc")):
        try:
            raw = http_get(f"https://addressesapi.090227.xyz/{path}", timeout=15)
            for line in raw.splitlines():
                m = re.match(r'(\d+\.\d+\.\d+\.\d+)(?:#\w+)?', line.strip())
                if m:
                    out.append((m.group(1), [443], "", tag))
        except Exception as e:
            print(f"[{tag}] 失败: {e}")
    print(f"[S7 CM-addressesapi] 候选 {len(out)}")
    return out

def src_svip():
    return _parse_plain_lines(
        "https://raw.githubusercontent.com/svip-s/cloudflare_ip/refs/heads/main/best_ips.txt", "svip-s")

# ---------- 主流程 ----------

def main():
    sources = [
        ("S1 CMzip", src_zip),
        ("S2 v2too", src_v2too),
        ("S3 danfeng2", lambda: src_tg_text("https://t.me/s/danfeng2", "danfeng2")),
        ("S4 cfyxip", lambda: src_tg_text("https://t.me/s/cfyxip", "cfyxip")),
        ("S5 Lancelot", src_lancelot),
        ("S6 BestCFip", src_joname1),
        ("S7 addressesapi", src_addressesapi),
        ("S8 svip-s", src_svip),
    ]

    raw_pool = []
    for name, fn in sources:
        try:
            raw_pool.extend(fn())
        except Exception as e:
            print(f"[{name}] 异常: {e}")

    print(f"\n原始候选合计: {len(raw_pool)}")

    # ---- 过滤 1+2+3：地区白名单 → 端口白名单 → IP 去重（保留最优端口）----
    dedup, dropped_region, dropped_port = {}, 0, 0
    for ip, ports, region_raw, tag in raw_pool:
        if not ip or not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            continue
        region = norm_region(region_raw)
        if not region or region not in REGION_QUOTA:
            dropped_region += 1
            continue
        # 端口白名单内全留（同 IP 不同端口=不同路由，分开保留）
        valid = [p for p in PORT_ORDER if p in set(ports or [])]
        if not valid:
            dropped_port += 1
            continue
        for port in valid:
            if port not in PORT_QUOTA:
                continue
            key = f"{ip}:{port}"
            if key in dedup:
                continue                  # 同 IP+端口重复，跳过
            dedup[key] = {"ip": ip, "port": port, "region": region, "tag": tag}

    print(f"地区过滤丢弃: {dropped_region} | 端口过滤丢弃: {dropped_port} | 去重后(IP+端口): {len(dedup)}")

    # ---- 地区配额主导 + 地区内多源轮询（保配比 + 保多样性）----
    from collections import defaultdict, Counter
    by_region = defaultdict(lambda: defaultdict(list))
    for rec in dedup.values():
        by_region[rec["region"]][rec["tag"]].append(rec)

    selected = []
    port_used = {p: 0 for p in PORT_QUOTA}
    for region, quota in REGION_QUOTA.items():
        src_map = by_region.get(region, {})
        # 每个源内部：端口优先级排序
        for tag in src_map:
            src_map[tag].sort(key=lambda x: PORT_ORDER.index(x["port"]) if x["port"] in PORT_ORDER else 99)
        picked, cursor = [], {t: 0 for t in src_map}
        while len(picked) < quota:
            progressed = False
            for tag in list(src_map.keys()):
                if len(picked) >= quota:
                    break
                # 跳过端口配额已满的候选
                while cursor[tag] < len(src_map[tag]):
                    cand = src_map[tag][cursor[tag]]
                    pk = cand["port"]
                    if port_used.get(pk, 0) < PORT_QUOTA.get(pk, 0):
                        break
                    cursor[tag] += 1
                if cursor[tag] < len(src_map[tag]):
                    cand = src_map[tag][cursor[tag]]
                    cursor[tag] += 1
                    port_used[cand["port"]] += 1
                    picked.append(cand)
                    progressed = True
            if not progressed:
                break                       # 该地区候选耗尽
        selected.extend(picked)
        if len(picked) < quota:
            print(f"[warn] {region} 仅 {len(picked)}/{quota}（候选不足）")

    # 若总数不足配额：从剩余候选补（严格不超总配额；按端口优先级）
    TOTAL_QUOTA = sum(REGION_QUOTA.values())
    if len(selected) < TOTAL_QUOTA:
        used = {f'{r["ip"]}:{r["port"]}' for r in selected}
        spare = [r for r in dedup.values() if f'{r["ip"]}:{r["port"]}' not in used]
        spare.sort(key=lambda x: (PORT_ORDER.index(x["port"]) if x["port"] in PORT_ORDER else 99))
        selected.extend(spare[: TOTAL_QUOTA - len(selected)])
    selected = selected[:TOTAL_QUOTA]

    # 输出国家码：机场码 → ISO 国家码（NRT/SIN/TPE 等机场码 cfnb 解析器不认）
    OUT_CODE = {"NRT": "JP", "JP": "JP", "TW": "TW", "SG": "SG", "US": "US"}
    lines = [f'{r["ip"]}:{r["port"]}#{OUT_CODE.get(r["region"], r["region"])}' for r in selected]

    # ---- 统计输出 ----
    from collections import Counter
    print("\n产出地区分布:", dict(Counter(r["region"] for r in selected)))
    print("产出端口分布:", dict(Counter(r["port"] for r in selected)))
    print("产出源分布:  ", dict(Counter(r["tag"] for r in selected)))

    if len(lines) < 90:
        print(f"[warn] 仅 {len(lines)}/90（源波动正常，下次运行自动补齐）")

    with io.open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n[done] 产出 {len(lines)} 个 → {OUT}")
    for l in lines:
        print("  ", l)

if __name__ == "__main__":
    main()