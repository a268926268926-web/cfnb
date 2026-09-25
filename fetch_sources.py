# -*- coding: utf-8 -*-
"""
fetch_sources.py — 多源聚合筛选器（全自动，产出 120 个候选池）

职责定位（2026-09-15 按用户口径修订）：
  聚合器只做三件"过滤"的事——去掉不要的地区、去掉不要的端口、去掉重复 IP。
  **不做质量裁决**：质量由下游 cfnb 实测（TCP→可用性→带宽）决定，实测才是唯一真东西。

源清单（活源，各自随上游实时更新；2026-09-22 求量扩源后共 23 个源槽位）：
  S1 zip.cm.edu.kg/all.json        CM 全量库（含 colo 落地字段；注：其 IP 为反代入口性质，实测可用）
  S2 ip.v2too.top/api/nodes        亦心の优选IP 官方接口（江西电信 500M 实测，carrier=ct）
  S3 t.me/s/danfeng2               丹枫频道（每 6h 精品 NRT 帖）
  S4 t.me/s/cfyxip                 亦心频道网页预览（每小时电信/移动榜单）
  S5 LancelotRar/best-cf-ips       聚合库（3h 扫描 top100）
  S6 joname1/BestCFip             聚合库（4h 构建，7 上游）
  S7 addressesapi.090227.xyz/ct|cmcc|cu   CM 分 ISP 库
  S8 svip-s/cloudflare_ip         每小时更新（陕西移动视角）
  S9  CF 官方段专用（090227/cu + ipdb bestcf）
  S10 CF 官方段随机采样（默认关）
  S11 良心云订阅（机场节点+实测双重优选）
  S12 ymyuuu-IPDB / S13 hubbylei-bestcf
  S14 优选域名解析（13 个公共优选域名 → 解析 → CF 段过滤）
  S15 优选订阅器解码（13 家，Mia 因 TG 门禁挂 dead）
  S16-S23 求量扩源批次（sanzang 元聚合/gslege 分国/luckyops/HHP/vipmc/辣子鸡全量/亚太top10/164746）

死源剔除：任何源或订阅器连续 10 轮 0 候选 → source_health.json 标 dead，不再拉取；
复活 = 删掉该键。

筛选规则：
  地区白名单（含配额）：NRT 32 / JP 14 / TW 14 / SG 20 / US 20 / ? 20 = 120
  端口优先级：443 > 2087 > 2053/2083/2096/8443
  去重：同 IP 只留一条，保留其最优端口
  产出：zip_nrt.txt（120 个，IP:port#国家码；无地区桶为裸 IP:PORT）
"""
import ipaddress, json, io, os, re, urllib.request

DIR = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(DIR, "zip_nrt.txt")
TIMEOUT = 60
UA = {"User-Agent": "Mozilla/5.0 cfnb-sources/3.0"}

# ---------- 筛选规则 ----------
# 无地区码的候选统一进这个桶：输出为裸 IP:PORT（不带 #），由国家交给 main.py 的
# 可用性检测 API 实测——只有它能给出"这个 IP:端口 真实的落地国家"。
UNKNOWN_REGION = "?"

# 冗余设计：cfnb 实测会淘汰一部分，故候选池按倍数供给（2026-09-22 求量扩源 90→120）
# "?" = 无地区码桶（优选订阅器里解出来的他人反代），输出裸 IP:PORT，国家交 main.py 实测
REGION_QUOTA = {"NRT": 32, "JP": 14, "TW": 14, "SG": 20, "US": 20, UNKNOWN_REGION: 20}   # 合计 120
PORT_QUOTA = {443: 80, 2087: 16, 2053: 8, 2083: 8, 2096: 4, 8443: 4}  # 端口配额（群实测优先级：443>2087>其余 TLS）
PORT_ORDER = [443, 2087, 2053, 2083, 2096, 8443]                  # 群实测：443 被 Q 最少，2087 次之
ALLOWED_PORTS = set(PORT_ORDER)
# 端口白名单豁免源：这些源的高端口条目放行（2026-09-16 用户拍板，仅丹枫）
PORT_EXEMPT_TAGS = {"danfeng2"}
PORT_EXEMPT_MAX = 6   # 豁免源的条目最多占几个名额，防刷屏

# 抓源允许走本地代理：这里只是取候选 IP 列表，不产生任何"速度/延迟"结论，
# 因此走代理不污染测速（测速的直连性由 run_and_shutdown.cmd 的 env 门槛 + main.py
# 链路体检闸门保证）。2026-09-16 实测：真直连时两个 t.me/s 频道源、BestCFip、svip-s
# 全部超时（WinError 10060/10054），90 个候选里 75 个来自 CMzip 一家——加回退才能保住多源。
PROXY_CANDIDATES = ["127.0.0.1:7890", "127.0.0.1:2080", "127.0.0.1:7897", "127.0.0.1:10808"]

# ============ 死源自动剔除（2026-09-22 用户拍板：连续 10 轮空/失败就不再拉） ============
# 记账在 source_health.json（本地不入库）。顶层源与 S15 内的每个订阅器各自记账；
# 连续 10 轮 0 候选 → dead=true，之后每轮直接跳过（打印一行可见）。
# 复活 = 手动删掉 JSON 里对应键（源生态有死而复生的先例，故不自动清理）。
HEALTH_FILE = os.path.join(DIR, "source_health.json")
CULL_AFTER_ZERO_ROUNDS = 10
HEALTH = {}          # 模块加载时读一次，main() 结束时写回


def _load_health():
    try:
        return json.load(io.open(HEALTH_FILE, encoding="utf-8"))
    except Exception:
        return {}


def health_ok(key):
    return not (HEALTH.get(key) or {}).get("dead")


def health_mark(key, ok):
    h = HEALTH.setdefault(key, {"zeros": 0})
    if ok:
        if h.get("zeros") or h.get("dead"):
            print(f"[健康] {key} 恢复出候选，计数清零")
        h["zeros"] = 0
        h["dead"] = False
    else:
        h["zeros"] = h.get("zeros", 0) + 1
        if h["zeros"] >= CULL_AFTER_ZERO_ROUNDS and not h.get("dead"):
            h["dead"] = True
            print(f"[健康] {key} 连续 {h['zeros']} 轮空/失败，标记 dead（此后跳过拉取）")


HEALTH = _load_health()   # 模块加载即读；main() 收尾写回


def _urlopen(req, timeout, proxy=None):
    """统一出口：强制 IPv4 解析。
    2026-09-17 实测（对照实验）：IPv6 本身可用（CF/GitHub 的 v6 TCP 0.08–0.27s），
    但同一 GitHub raw 走 v4 只要 1.59s、默认（含 v6 候选）要 15.31s → 抓源一律走 v4，图快也图稳。"""
    import socket as _s
    orig = _s.getaddrinfo

    def gai_v4(host, port, family=0, type=0, proto=0, flags=0):
        return orig(host, port, _s.AF_INET, type, proto, flags)

    _s.getaddrinfo = gai_v4
    try:
        if proxy:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
            return opener.open(req, timeout=timeout)
        return urllib.request.urlopen(req, timeout=timeout)
    finally:
        _s.getaddrinfo = orig


def http_get(url, timeout=TIMEOUT):
    try:
        return _urlopen(urllib.request.Request(url, headers=UA), timeout)\
            .read().decode("utf-8", errors="ignore")
    except Exception as direct_err:
        # 注意：绝不能只把最后一个代理错误抛出去——那会把直连的真实原因盖成"10061 连接被拒"
        # （2026-09-17 踩过：127.0.0.1 代理端口没人监听时抛的正是 10061，误导排查方向）
        tried = []
        for p in PROXY_CANDIDATES:
            try:
                body = _urlopen(urllib.request.Request(url, headers=UA), timeout,
                                proxy=f"http://{p}").read().decode("utf-8", errors="ignore")
                print(f"[源抓取] {url} 直连失败({type(direct_err).__name__})，经本地代理 {p} 取回")
                return body
            except Exception as e:
                tried.append(f"{p}={type(e).__name__}")
        raise RuntimeError(f"直连失败: {type(direct_err).__name__} {str(direct_err)[:80]} | 代理回退: {', '.join(tried) or '无'}")


# ============ CF 官方段配额（2026-09-18 加，治"IP 死得快"） ============
# 实测根因：第三方源（VPS789/辣子鸡/TG 频道）里大量是**他人 VPS 上的 TLS 透传反代**
# （AS212336 ByteVirt / AS16509 Amazon / AS132203 腾讯云…），不是 CF 边缘。那台机器
# 一关/被墙就死 → 24h 死亡率 20%。CF 官方段（AS13335）的 IP 不会被主人关掉，只会因
# 路由/QoS 变慢。故：官方段占配额大头，非官方段留一小份（它们常走优化线路、更快）。
CF_RANGES_URL = "https://www.cloudflare.com/ips-v4"
CF_RANGES_CACHE = "cf_ranges.txt"
CF_OFFICIAL_QUOTA = 0.5      # 只约束"候选池入场"：保证官方段有足够样本进终选去竞技。
                             # 终选配比由 main.py 的 CF_OFFICIAL_RATIO 决定（现为 0=纯分数）。
                             # 2026-09-18 修：0.7 硬配额会把能用的
                             # 他人反代挤出候选池，而随机采样的官方 IP 多数过不了带宽测试
                             # → 池子从 30 塌到 7。改成 50/50 让实测裁决，官方段另有软加分）


def cf_official_nets():
    """CF 官方 IPv4 段（15 段左右）；缓存 24h，取不到就返回 None=不过滤"""
    import ipaddress, os, time as _t
    try:
        if os.path.exists(CF_RANGES_CACHE) and _t.time() - os.path.getmtime(CF_RANGES_CACHE) < 86400:
            txt = io.open(CF_RANGES_CACHE, encoding="utf-8").read()
        else:
            txt = http_get(CF_RANGES_URL, timeout=20)
            io.open(CF_RANGES_CACHE, "w", encoding="utf-8", newline="").write(txt)
        nets = [ipaddress.ip_network(l.strip()) for l in txt.splitlines() if l.strip()]
        return nets or None
    except Exception as e:
        print("[官方段] 取 ips-v4 失败(%s)，本轮不做官方段过滤" % type(e).__name__)
        return None


def is_official(ip, nets):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in nets)
    except Exception:
        return False


# 落地区域归一：把各种来源的地区标识统一成 NRT/JP/TW/SG/US（其余丢弃）
# 键同时收"国家码"和"CF 机房 IATA 码"——两者都是同一个语义（这条候选的落地区域），
# 归一后只留 5 个桶，别的桶（HKG/ICN/FRA…）在下面按"不在 REGION_QUOTA"丢弃。
REGION_ALIAS = {
    "NRT": "NRT", "JP": "JP", "JPN": "JP", "JAPAN": "JP", "TOKYO": "JP", "OSAKA": "JP",
    "KIX": "JP", "FUK": "JP", "CTS": "JP", "NGO": "JP", "ITM": "JP",   # 其余日本机房
    "TW": "TW", "TWN": "TW", "TAIWAN": "TW", "TPE": "TW", "TAIPEI": "TW",
    "KHH": "TW", "TSA": "TW", "RMQ": "TW",                            # 高雄/松山/台中
    "SG": "SG", "SGP": "SG", "SIN": "SG", "SINGAPORE": "SG",
    "US": "US", "USA": "US", "LAX": "US", "SJC": "US", "SEA": "US", "SFO": "US",
    "IAD": "US", "EWR": "US", "ORD": "US", "DFW": "US", "ATL": "US", "MIA": "US",
    "DEN": "US", "PHX": "US", "SLC": "US", "MSP": "US", "DTW": "US", "BOS": "US",
    "PHL": "US", "SAN": "US", "PDX": "US", "AUS": "US", "LAS": "US", "STL": "US",
    "CLT": "US", "BNA": "US", "IAH": "US", "MCI": "US", "IND": "US", "CMH": "US",
    "RDU": "US", "TPA": "US", "MCO": "US", "BWI": "US", "CLE": "US", "PIT": "US",
    "HNL": "US", "ANC": "US", "SAT": "US", "MSY": "US", "JAX": "US", "ABQ": "US",
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
        d = json.loads(http_get("https://ip.v2too.top/api/nodes", timeout=20))
        # 该接口换过形态：旧=扁平列表；新={"ct":[...],"cm":[...],"cu":[...]}（每项仍带 carrier 字段）
        rows = []
        if isinstance(d, dict):
            for arr in d.values():
                if isinstance(arr, list):
                    rows.extend(x for x in arr if isinstance(x, dict))
        elif isinstance(d, list):
            rows = [x for x in d if isinstance(x, dict)]
        ct = [x for x in rows if x.get("carrier") == "ct" and x.get("speed", 0) > 0.05]
        ct.sort(key=lambda x: -x.get("speed", 0))
        out = [(x["ip"], [443], x.get("region", ""), "v2too") for x in ct]
        print(f"[S2 v2too] 候选 {len(out)}")
        return out
    except Exception as e:
        print(f"[S2 v2too] 失败: {e}")
        return []

def _ips_from_text(text, tag, out, seen):
    region_hint = ""
    for kw, code in (("日本", "NRT"), ("东京", "NRT"), ("新加坡", "SG"), ("台湾", "TW"),
                     ("香港", "HK"), ("美国", "US"), ("洛杉矶", "US")):
        if kw in text:
            region_hint = code
            break
    # 频道帖子的端口常与 IP 分开写（"🔌 端口: 62668"），必须单独抓：
    # 否则会被当成 443 处理 → 制造出"端口错了的节点"（2026-09-16 发现）
    mp = re.search(r'(?:端口|Port)\s*[:：]?\s*(\d{2,5})', text)
    explicit_port = int(mp.group(1)) if mp else None
    for m in re.finditer(r'\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{2,5}))?\b', text):
        ip = m.group(1)
        if ip in seen:
            continue
        seen.add(ip)
        ports = [int(m.group(2))] if m.group(2) else ([explicit_port] if explicit_port else [443])
        out.append((ip, ports, region_hint, tag))


def src_tg_text(urls, tag):
    """urls = 依次尝试的入口列表。第一条是 t.me/s 网页预览，第二条是 tg.i-c-a.su 免登录 JSON。
    真直连下 t.me/s 会 10060 超时（2026-09-16 实测），冷机轮次没有本地代理时靠备用入口兜底。"""
    if isinstance(urls, str):
        urls = [urls]
    raw, used = None, None
    for url in urls:
        for attempt in range(1, 3):
            try:
                raw, used = http_get(url, timeout=25), url
                break
            except Exception as e:
                print(f"[{tag}] {url} 第{attempt}次失败: {e}")
        if raw is not None:
            break
    if raw is None:
        return []
    out, seen = [], set()
    try:
        if "i-c-a.su" in (used or ""):                       # 免登录 JSON 接口
            data = json.loads(raw)
            msgs = data.get("messages") or data.get("data") or []
            for m in reversed(msgs):                          # 倒序 = 最新帖优先
                # 该接口的正文字段是 message（不是 text），且内容带 HTML 标签，需与网页预览同样清洗
                body = str(m.get("message") or m.get("text") or "")
                _ips_from_text(re.sub(r'█+', ' ', re.sub(r'<[^>]+>', ' ', body)), tag, out, seen)
        else:                                                 # t.me/s 网页预览
            for b in reversed(re.findall(r'tgme_widget_message_text[^>]*>(.*?)</div>', raw, re.S)):
                _ips_from_text(re.sub(r'█+', ' ', re.sub(r'<[^>]+>', ' ', b)), tag, out, seen)
        print(f"[{tag}] 候选 {len(out)}" + ("" if used == urls[0] else f"（备用入口 {used.split('/')[2]}）"))
        return out
    except Exception as e:
        print(f"[{tag}] 解析失败: {e}")
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
    for path, tag in (("ct", "CM-ct"), ("cmcc", "CM-cmcc"), ("cu", "CM-cu")):
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


def src_liangxin():
    """良心云订阅源（2026-09-19 用户建议：机场节点+cfnb 实测=双重优选，最精准）
    URL: https://liangxin.xyz/api/v1/liangxin?OwO=c5c2027f96d94459a9ee323409b3c424
    特点：35 个 VLESS 节点，很多是 CTCU/CMCU 三网互联优化线（比直连强）
    流程：拉订阅→base64 解码→提取 IP:PORT→喂给 cfnb 实测
    """
    try:
        url = "https://liangxin.xyz/api/v1/liangxin?OwO=c5c2027f96d94459a9ee323409b3c424"
        data = http_get(url, timeout=20)
        import base64
        decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
        out = []
        for line in decoded.splitlines():
            if not line.strip(): continue
            # vless://uuid@ip:port?xxx#备注
            if line.startswith('vless://'):
                m = re.search(r'@([^:]+):(\d+)', line)
                if m:
                    ip_or_domain = m.group(1)
                    port = int(m.group(2))
                    # 如果是 IP，直接用；如果是域名，标记一下（cfnb 会解析成 IP）
                    if re.match(r'\d+\.\d+\.\d+\.\d+', ip_or_domain):
                        out.append((ip_or_domain, [port], "", "LX-良心云"))
                    else:
                        # 域名形式，让 cfnb 的 DNS 解析器处理
                        out.append((ip_or_domain, [port], "", "LX-域名"))
        print(f"[S9 良心云] 候选 {len(out)} 个节点 (IP+ 域名混合)")
        return out
    except Exception as e:
        print(f"[S9 良心云] 失败：{e}")
        return []

def src_ymyuuu():
    return _parse_plain_lines(
        "https://raw.githubusercontent.com/ymyuuu/IPDB/main/bestcf.txt", "ymyuuu-IPDB")

def src_hubbylei():
    return _parse_plain_lines(
        "https://raw.githubusercontent.com/hubbylei/bestcf/main/bestcf.txt", "hubbylei-bestcf")


# ============ 2026-09-22 求量扩源批次（全部 GitHub Actions 定时自动更新，逐个验活过格式） ============
# 口径不变：聚合器只过滤不裁决，备注/标签只当地区提示，最终质量由 cfnb 实测判定。

def src_sanzang():
    """多公开优选项目元聚合（每 8h）：IP:port#国家码+旗子。294 条，2026-09-21 仍在更新。
    注意：混有 AWS/Oracle 段（3.112.x 等）——有地区标签的照标签进地区门，实测裁决。"""
    return _parse_plain_lines(
        "https://raw.githubusercontent.com/sanzang-tango/best-cf-ip/main/best-cf-ipv4.txt", "sanzang")

def src_gslege():
    """分国家每小时优选（JP/SG/US 三个白名单内文件；DE/NL 不在白名单不拉）。"""
    out = []
    for cc in ("JP", "SG", "US"):
        out += _parse_plain_lines(
            f"https://raw.githubusercontent.com/gslege/CloudflareIP/main/{cc}.txt", f"gslege-{cc}")
    return out

def src_luckyops():
    """cf-pool（自动扫描，明说供 edgetunnel ADDAPI 用）：纯 IP:443 无标签。"""
    return _parse_plain_lines(
        "https://raw.githubusercontent.com/luckyops/cf-pool/main/all.txt", "luckyops")

def src_hhp():
    """HHP-cf-ips（自动测速）：IP:443#中文备注，备注不当地区用。"""
    return _parse_plain_lines(
        "https://raw.githubusercontent.com/jifengwind/HHP-cf-ips/main/ips.txt", "HHP")

def src_vipmc():
    """cf_best_ip（自动更新，首行是日期行，解析器自动跳过）：IP#中文备注。"""
    return _parse_plain_lines(
        "https://raw.githubusercontent.com/vipmc838/cf_best_ip/main/cloudflare_bestip.txt", "vipmc")

def src_lzj_all():
    """辣子鸡优选原始全量文件（其订阅器的上游）：IP:443#中文备注，混时间戳行自动跳过。
    订阅器版（S15 里的 sub.lzjbaby.com）是它筛过的子集，这里拿全量。"""
    return _parse_plain_lines("https://bestcf.pages.dev/lzj/all.txt", "lzj-全量")

def src_weduolijia():
    """亚太 CF 优选（自动更新）：取 top10 精选档，all.txt 太大留作后备。"""
    return _parse_plain_lines(
        "https://raw.githubusercontent.com/weduolijia/-CF-IP/main/top10.txt", "weduolijia")

def src_ip164746():
    """ip.164746.xyz 榜单页：逗号分隔裸 IP（ipTop10.html），无端口无地区。"""
    try:
        raw = http_get("https://ip.164746.xyz/ipTop10.html", timeout=15)
        out = []
        for ip in re.findall(r'(\d{1,3}(?:\.\d{1,3}){3})', raw):
            out.append((ip, [443], "", "164746"))
        print(f"[164746] 候选 {len(out)}")
        return out
    except Exception as e:
        print(f"[164746] 失败: {e}")
        return []


# ============ 优选域名解析（2026-09-20 加，补"三测"里缺的那一测） ============
# 背景：自建动态优选域名的 A 记录只能放 IPv4；公共优选域名是"会定期换 IP 的入口"，
# 它的价值恰恰是解析出来的那批 IP 是别人替我们按运营商挑过的。所以正确做法不是
# 把域名当节点，而是【解析→拿到 CF 边缘 IP→丢进 cfnb 实测池→按分数决定进不进 A 记录】。
# 解析不出 / 解析到非 CF 段的（如机场自己的域名 jp1-lx.7770006.xyz），不在此列——
# 那是真节点，走订阅源分支处理，这里只收"优选域名"这一语义。
PREFERRED_DOMAINS = [
    # 090227 系（实测存活，分运营商；页面 §2.1）
    ("cf.090227.xyz", 443, "PD-090227通用"),
    ("ct.090227.xyz", 443, "PD-090227电信"),
    ("cu.090227.xyz", 443, "PD-090227联通"),
    # 秋名山系（cf 通用存活；ct/cu/cmcc SNI 门控，curl 连不上但解析正常）
    ("cf.877774.xyz", 443, "PD-秋名山通用"),
    ("ct.877774.xyz", 443, "PD-秋名山电信"),
    # 0sm 加速解析页
    ("cf.0sm.com", 443, "PD-0sm"),
    # VPS789 top10 里的域名（bestcf.pages.dev 当日清单，实测全解析到 CF 段）
    ("cfsaas.080112.xyz", 443, "PD-VPS789"),
    ("cf.godns.cc", 443, "PD-VPS789"),
    ("yg12.ygkkk.dpdns.org", 443, "PD-VPS789"),
    ("china-telecom.cname.cloudflare.468123.xyz", 443, "PD-VPS789"),
    # 2026-09-22 扩源批次（probe 实测均解析到 CF 段）
    ("bestcf.top", 443, "PD-bestcf"),
    ("cloudflare.182682.xyz", 443, "PD-182682"),
    ("youxuan.cf.090227.xyz", 443, "PD-090227泛"),
]

def _resolve_v4(host):
    """强制 IPv4 解析一个域名的全部 A 记录；失败返回 []。"""
    import socket as _s
    orig = _s.getaddrinfo
    try:
        _s.getaddrinfo = lambda h, p, *a, **k: orig(h, p, _s.AF_INET, *a[2:], **{x: k[x] for x in k if x != 'family'})
        infos = _s.getaddrinfo(host, None, _s.AF_INET)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []
    finally:
        _s.getaddrinfo = orig

def src_preferred_domains(nets=None):
    """优选域名 → 解析 → 只保留落在 CF 官方段的 IP → 喂进候选池。
    地区留空：CF anycast 落地由下游 main.py 按 exit 国家纠正（与 src_cf_official 同一口径）。"""
    if nets is None:
        nets = cf_official_nets()
    out, seen = [], set()
    n_dom_ok = 0
    for host, port, tag in PREFERRED_DOMAINS:
        ips = _resolve_v4(host)
        kept = 0
        for ip in ips:
            if ip in seen:
                continue
            if nets and not is_official(ip, nets):
                continue              # 解析到非 CF 段的不算"优选域名"，丢弃
            seen.add(ip)
            out.append((ip, [port], "", tag))
            kept += 1
        if kept:
            n_dom_ok += 1
        print(f"[{tag}] {host} 解析 {len(ips)} 个IP，CF段保留 {kept}")
    print(f"[S12 优选域名] 候选 {len(out)}（{n_dom_ok}/{len(PREFERRED_DOMAINS)} 个域名有可用CF段）")
    return out


def src_cf_official():
    """CF 官方段专用源（2026-09-18 加，治"IP 死得快"的根因）：
    实测第三方"优选 IP"列表 99% 是他人 VPS 反代（AS212336/AS16509/AS132203…），
    主人一关机就死；这两个源实测 100% 落在 CF 官方 15 段内（AS13335）：
      cf.090227.xyz/cu  联通优选（官方段，8/8）
      ipdb bestcf       官方 IP 优选（10/10，60 分钟更新）"""
    out = []
    for url, tag in (("https://cf.090227.xyz/cu?ips=8&port=443", "CF-cu官方"),
                     ("https://ipdb.api.030101.xyz/?type=bestcf", "CF-ipdb官方")):
        try:
            raw = http_get(url, timeout=15)
            n0 = len(out)
            for line in raw.splitlines():
                m = re.match(r'(\d+\.\d+\.\d+\.\d+)', line.strip())
                if m:
                    out.append((m.group(1), [443], "", tag))
            print(f"[{tag}] 候选 {len(out)-n0}")
        except Exception as e:
            print(f"[{tag}] 失败: {e}")
    return out

CF_SAMPLE_N = 0          # 官方段随机采样：关（2026-09-18 实测 2200 个采样只有 33 个建链、0 个过带宽关，官方 IP 要靠精选名单）
CF_SAMPLE_REGION = "NRT" # 采样条目统一预标 NRT，真实落地由 main.py 用可用性检测的 exit 国家纠正


def src_cf_sample(n=CF_SAMPLE_N):
    """从 CF 官方 15 段随机采样 IP（CloudflareSpeedTest 的标准做法）。
    2026-09-18 实测：第三方源里官方段只占约 1%（24/2301），光靠别人给的列表
    永远凑不出以官方段为主的池子 —— 而反代 IP 的死法正是"主人关机就死"。"""
    nets = cf_official_nets()
    if not nets or n <= 0:
        return []
    import random
    weights = [min(int(x.num_addresses), 1 << 20) for x in nets]   # 按地址数加权，避免小段被过度代表
    picked, seen, tries = [], set(), 0
    while len(picked) < n and tries < n * 30:
        tries += 1
        net = random.choices(nets, weights=weights)[0]
        ip = str(net[random.randrange(net.num_addresses)])
        if ip in seen:
            continue
        seen.add(ip)
        picked.append((ip, [443], CF_SAMPLE_REGION, "CF官方采样"))
    print(f"[S10 CF官方采样] 候选 {len(picked)}（{len(nets)} 个官方段，试采 {tries} 次）")
    return picked

# ============ 官方段落地实测（2026-09-21 加，替掉原来的假标签） ============
# 原来的做法是给"没有地区码但属 CF 官方段"的条目硬塞 region="JP"，理由写的是
# "下游 relabel_by_exit 会按真实 exit 纠正"——**这条理由不成立**：官方段在 main.py
# 里被豁免了可用性检测（真 CF 边缘不是开放代理，API 必然判失败），因此永远没有
# exit_details，relabel_by_exit 无从纠正，假 #JP 会一路写进 ip.txt 和订阅名字。
# 官方段是 anycast，IP 本身确实没有国家；唯一诚实且与延迟直接相关的量是
# "从本机出发落在哪个 CF 机房（colo）"——这正是用户说的"物理距离"判据。
# 实测口径与客户端完全一致：TCP 直连该 IP，TLS SNI 用公共 CF 域名，读 /cdn-cgi/trace。
# 2026-09-21 实测 15/15 有响应，且能区分（LAX 8 / FRA 7）→ 有区分力，可用。
COLO_PROBE_HOST = "speed.cloudflare.com"
COLO_PROBE_WORKERS = 12
COLO_PROBE_TIMEOUT = 6
# 与 main.py 的"链路体检闸门"同一判据：直连场景下境外 IP 不可能是个位数 ms，
# 出现即说明流量被 TUN/代理劫持 —— 此时 colo 量到的是**代理出口**的机房（同一 IP
# 会在 LAX/FRA 之间乱跳，2026-09-21 实测到），不是真实线路，必须整体作废而不是照写。
HIJACK_TCP_MS = 10


def _probe_colo(ip):
    """返回 (colo, tcp_ms)；失败返回 ("", None)。tcp_ms 同时用作劫持判据。"""
    import socket as _s, ssl as _ssl, time as _t
    tcp_ms = None
    try:
        t0 = _t.time()
        raw = _s.create_connection((ip, 443), timeout=COLO_PROBE_TIMEOUT)
        tcp_ms = (_t.time() - t0) * 1000
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        with ctx.wrap_socket(raw, server_hostname=COLO_PROBE_HOST) as tls:
            tls.settimeout(COLO_PROBE_TIMEOUT)
            tls.sendall(("GET /cdn-cgi/trace HTTP/1.1\r\nHost: %s\r\n"
                         "Connection: close\r\n\r\n" % COLO_PROBE_HOST).encode())
            buf = b""
            while b"\r\n\r\n" not in buf and len(buf) < 65536:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                buf += chunk
        m = re.search(rb'^colo=(\S+)', buf, re.M)
        return (m.group(1).decode() if m else ""), tcp_ms
    except Exception:
        return "", tcp_ms


def probe_colos(ips):
    """并发实测一批 IP 的 colo，返回 {ip: colo}（被劫持时返回 {} = 全部作废）。"""
    from concurrent.futures import ThreadPoolExecutor
    res, unmapped = {}, {}
    with ThreadPoolExecutor(max_workers=COLO_PROBE_WORKERS) as ex:
        for ip, (colo, tcp_ms) in zip(ips, ex.map(_probe_colo, ips)):
            res[ip] = (colo, tcp_ms)
    lats = sorted(v[1] for v in res.values() if v[1] is not None)
    if lats and lats[len(lats) // 2] < HIJACK_TCP_MS:
        raise RuntimeError(
            f"TCP 中位延迟 {lats[len(lats)//2]:.1f}ms < {HIJACK_TCP_MS}ms —— 本机流量被 TUN/代理劫持，"
            f"colo 反映的是代理出口而非真实线路（实测同一 IP 会在 LAX/FRA 间乱跳）。"
            f"本轮不产出、不覆盖 zip_nrt.txt（否则假地区会一路写进 ip.txt 与订阅名字）。"
            f"请在直连环境重跑。")
    out = {}
    for ip, (colo, _t) in res.items():
        out[ip] = colo
        if not norm_region(colo):
            unmapped[colo or "(无响应)"] = unmapped.get(colo or "(无响应)", 0) + 1
    ok = sum(1 for c in out.values() if norm_region(c))
    print(f"[官方段落地] 实测 colo {len(ips)} 个：可归入白名单 {ok}"
          + (f"，其余丢弃 {unmapped}（机房不在 JP/TW/SG/US，按物理距离过滤）" if unmapped else ""))
    return out


# ============ 优选订阅器解码（2026-09-21 加，第三测） ============
# 协议来源：edgetunnel `_worker.js:5928` 获取优选订阅生成器数据 —— 订阅器把"优选 IP"
# 以 vless 链接形式返回，其中【同时含占位 UUID 和 example.com】的行才是优选 IP，
# 地址在 `@` 与 `?` 之间。抓取形态与上游面板填 `sub://` 时完全一致（同 URL 同 UA），
# 属于"读一次列表"，不做探测/测速，不给上游增加额外负担。
SUB_PLACEHOLDER_UUID = "00000000-0000-4000-8000-000000000000"
SUB_UA = {"User-Agent": "v2rayN/edgetunnel (https://github.com/cmliu/edgetunnel)"}
PREFERRED_SUBS = [
    ("Kristi", "https://sub.mot.cloudns.biz"),
    ("辣椒炒肉", "https://sub.xdu.qzz.io"),
    ("cmin2", "https://cmin2.cc.cd"),
    ("58807", "https://58807.cc.cd"),
    ("CM官方", "https://sub.cmliussss.net"),
    ("Moist_R", "https://owo.o00o.ooo"),
    ("洛璃", "https://loli.sub.us.ci"),
    ("辣子鸡", "https://sub.lzjbaby.com"),
    ("S5公益", "https://sub.995677.xyz"),
    ("周润发", "https://zrf.zrf.me"),
    ("DanFeng", "https://sub.danfeng.eu.org"),
    ("天诚", "https://cm.soso.edu.kg"),
    # 2026-09-22：Mia 的 /sub 对所有 UA 一律 302 跳 t.me/MiaChatChannel（改 TG 门禁分发），
    # 标准协议解不动。保留在列里等其恢复；health 文件里已置 dead 免每轮空跑。
    ("Mia", "https://sub.mia.xx.kg"),
]


def _decode_pref_sub(host):
    """解一个优选订阅器，返回 [(地址, 端口, 备注解码后)]；地址可能是 IP 也可能是域名。
    备注必须 urldecode 后再交地区判定：订阅器把备注写成 %F0%9F%87%A9%F0%9F%87%AA 德国
    这种百分号编码，直接拿编码串去 norm_region 永远匹配不到 → 全部误入 ? 桶
    （2026-09-21 实测踩到，产出 0 个带地区的订阅器条目）。"""
    import base64, urllib.parse
    url = f"{host.rstrip('/')}/sub?host=example.com&uuid={SUB_PLACEHOLDER_UUID}"
    raw = _urlopen(urllib.request.Request(url, headers=SUB_UA), 25)\
        .read().decode("utf-8", "replace").strip()
    body = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace")
    out = []
    for line in body.replace("\r\n", "\n").split("\n"):
        if SUB_PLACEHOLDER_UUID not in line or "example.com" not in line:
            continue                      # 非优选 IP 行（真节点链接）不属于本源的语义
        m = re.search(r'://[^@]+@([^?]+)', line)
        if not m:
            continue
        addr = m.group(1)
        hm = re.search(r'#(.+)$', line)
        remark = urllib.parse.unquote(hm.group(1)) if hm else ""
        if ":" not in addr:
            addr, port = addr, 443
        else:
            addr, port = addr.rsplit(":", 1)
            if not port.isdigit():
                continue
        out.append((addr, int(port), remark))
    return out


def src_preferred_subs():
    """第三测：优选订阅器展开成候选。IP 形式的直接进池；域名形式的先解析成 IPv4
    （订阅器自己的优选域名如 cmin2.cc.cd 就在这一列）。
    地区一律留空，交给下面统一的地区门处理（官方段→colo 实测；他人反代→裸行交
    main.py 的可用性 API 实测真实落地）。"""
    out = []
    for name, host in PREFERRED_SUBS:
        key = f"订阅器:{name}"
        if not health_ok(key):
            print(f"[订阅器 {name}] dead（连续 {CULL_AFTER_ZERO_ROUNDS} 轮无候选），跳过")
            continue
        try:
            entries = _decode_pref_sub(host)
        except Exception as e:
            print(f"[订阅器 {name}] 失败: {type(e).__name__} {str(e)[:60]}")
            health_mark(key, False)
            continue
        health_mark(key, bool(entries))
        n_ip = n_dom = 0
        for addr, port, remark in entries:
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', addr):
                out.append((addr, [port], norm_region(remark) or "", f"SUB-{name}"))
                n_ip += 1
            else:
                for ip in _resolve_v4(addr):
                    out.append((ip, [port], norm_region(remark) or "", f"SUB-{name}"))
                    n_dom += 1
        print(f"[订阅器 {name}] 展开 {len(entries)} 条 → IP {n_ip} + 域名解析 {n_dom}")
    print(f"[S15 优选订阅器] 候选 {len(out)}（{len(PREFERRED_SUBS)} 个订阅器）")
    return out


# ---------- 主流程 ----------

def main():
    sources = [
        ("S1 CMzip", src_zip),
        ("S2 v2too", src_v2too),
        ("S3 danfeng2", lambda: src_tg_text(["https://t.me/s/danfeng2",
                                             "https://tg.i-c-a.su/json/danfeng2"], "danfeng2")),
        ("S4 cfyxip", lambda: src_tg_text(["https://t.me/s/cfyxip",
                                           "https://tg.i-c-a.su/json/cfyxip"], "cfyxip")),
        ("S5 Lancelot", src_lancelot),
        ("S6 BestCFip", src_joname1),
        ("S7 addressesapi", src_addressesapi),
        ("S8 svip-s", src_svip),
        ("S9 CF 官方段", src_cf_official),
        ("S10 CF 官方采样", src_cf_sample),
        ("S11 良心云", src_liangxin),
        ("S12 ymyuuu-IPDB", src_ymyuuu),
        ("S13 hubbylei-bestcf", src_hubbylei),
        ("S14 优选域名", src_preferred_domains),
        ("S15 优选订阅器", src_preferred_subs),
        # 2026-09-22 求量扩源批次（全部 Actions 自动更新、验活过）
        ("S16 sanzang聚合", src_sanzang),
        ("S17 gslege分国", src_gslege),
        ("S18 luckyops池", src_luckyops),
        ("S19 HHP测速", src_hhp),
        ("S20 vipmc", src_vipmc),
        ("S21 辣子鸡全量", src_lzj_all),
        ("S22 亚太top10", src_weduolijia),
        ("S23 164746榜", src_ip164746),
    ]

    raw_pool = []
    empty_sources = []
    for name, fn in sources:
        if not health_ok(name):
            print(f"[{name}] dead（连续 {CULL_AFTER_ZERO_ROUNDS} 轮空/失败），跳过拉取")
            continue
        try:
            got = fn()
            if not got:
                empty_sources.append(name)
            raw_pool.extend(got)
            health_mark(name, bool(got))
        except Exception as e:
            empty_sources.append(name)
            health_mark(name, False)
            print(f"[{name}] 异常: {e}")

    print(f"\n原始候选合计: {len(raw_pool)}")
    print(f"源健康度: 存活 {len(sources) - len(empty_sources)}/{len(sources)}"
          + (f" | 空或失败: {', '.join(empty_sources)}" if empty_sources else ""))

    # ---- 过滤 1+2+3：地区白名单 → 端口白名单 → IP 去重（保留最优端口）----
    # CF 官方段网表提前获取：既供下面的地区门判定，又供后段的官方段保底再平衡复用。
    nets = cf_official_nets()

    # 无地区码的官方段条目：先并发实测 colo（唯一诚实且与延迟相关的地区判据），
    # 再进下面的地区门。非官方段的无地区码条目不走这里——它们由 main.py 的
    # 可用性 API 实测真实落地国家（那条路对官方段无效、对反代有效，正好互补）。
    _need_colo = []
    for ip, _ports, region_raw, _tag in raw_pool:
        if not ip or not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            continue
        if norm_region(region_raw):
            continue
        if nets is not None and is_official(ip, nets):
            _need_colo.append(ip)
    colo_map = probe_colos(sorted(set(_need_colo))) if _need_colo else {}

    dedup, dropped_region, dropped_port = {}, 0, 0
    for ip, ports, region_raw, tag in raw_pool:
        if not ip or not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            continue
        region = norm_region(region_raw)
        if not region or region not in REGION_QUOTA:
            # 官方段：用实测 colo 定地区（不落白名单机房的一律丢，见 probe_colos 注释）；
            # 他人反代：进 "?" 桶，输出裸行，国家由 main.py 实测。
            if nets is not None and is_official(ip, nets):
                region = norm_region(colo_map.get(ip, ""))
            else:
                region = UNKNOWN_REGION
            if not region or region not in REGION_QUOTA:
                dropped_region += 1
                continue
        # 端口白名单内全留（同 IP 不同端口=不同路由，分开保留）
        # 例外：丹枫"精品单发"帖子天生用高端口（8581/39257/62668…），按 2026-09-16 用户拍板
        # 给它单开放行，端口对不对交给下游实测裁决（443 优先的定调只针对常规优选源）
        valid = [p for p in PORT_ORDER if p in set(ports or [])]
        exempt = tag in PORT_EXEMPT_TAGS
        if not valid and exempt:
            valid = sorted({p for p in (ports or []) if 1 <= p <= 65535})
        if not valid:
            dropped_port += 1
            continue
        for port in valid:
            if port not in PORT_QUOTA and not exempt:
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
    exempt_used = 0
    for region, quota in REGION_QUOTA.items():
        src_map = by_region.get(region, {})
        # "?" 桶（订阅器解出来的他人反代）不受端口配额约束：它的条目几乎全是 443，
        # 而 443 的配额会被排在前面的地区桶吃光 → 整桶饿死（2026-09-21 实测产出 0 个，
        # 16 个名额被补位逻辑塞成了 SG）。端口配额的本意是"别让池子全是高端口"，
        # 放行 443 只会更符合本意，故这里直接豁免。
        _port_free = (region == UNKNOWN_REGION)
        # 每个源内部：端口优先级排序
        for tag in src_map:
            src_map[tag].sort(key=lambda x: PORT_ORDER.index(x["port"]) if x["port"] in PORT_ORDER else 99)
        picked, cursor = [], {t: 0 for t in src_map}
        while len(picked) < quota:
            progressed = False
            for tag in list(src_map.keys()):
                if len(picked) >= quota:
                    break
                # 跳过端口配额已满的候选（豁免源不看端口配额，只受 PORT_EXEMPT_MAX 总量约束）
                while cursor[tag] < len(src_map[tag]):
                    cand = src_map[tag][cursor[tag]]
                    pk = cand["port"]
                    if _port_free or cand.get("tag") in PORT_EXEMPT_TAGS:
                        break
                    if port_used.get(pk, 0) < PORT_QUOTA.get(pk, 0):
                        break
                    cursor[tag] += 1
                if cursor[tag] < len(src_map[tag]):
                    cand = src_map[tag][cursor[tag]]
                    is_exempt = cand.get("tag") in PORT_EXEMPT_TAGS
                    if is_exempt and exempt_used >= PORT_EXEMPT_MAX:
                        cursor[tag] += 1
                        continue
                    cursor[tag] += 1
                    port_used[cand["port"]] = port_used.get(cand["port"], 0) + 1
                    if is_exempt:
                        exempt_used += 1
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

    # ---- CF 官方段保底再平衡（不推翻上面的地区/端口配比）----
    # nets already fetched above; reuse for efficiency
    if nets and selected:
        need_official = int(TOTAL_QUOTA * CF_OFFICIAL_QUOTA + 0.999)
        off = [r for r in selected if is_official(r["ip"], nets)]
        non = [r for r in selected if not is_official(r["ip"], nets)]
        if len(off) < need_official:
            used = {f'{r["ip"]}:{r["port"]}' for r in off + non}
            extra = [r for r in dedup.values()
                     if f'{r["ip"]}:{r["port"]}' not in used and is_official(r["ip"], nets)]
            extra.sort(key=lambda x: (PORT_ORDER.index(x["port"]) if x["port"] in PORT_ORDER else 99))
            off.extend(extra[: need_official - len(off)])
            non = non[: max(0, TOTAL_QUOTA - len(off))]      # 官方段挤掉的是非官方尾部
            selected = (off + non)[:TOTAL_QUOTA]
        _n_off = sum(1 for r in dedup.values() if is_official(r["ip"], nets))
        print(f"[官方段] 候选 {_n_off}/{len(dedup)} 属 CF 官方段(AS13335)；"
              f"产出 {len(off)} 官方 + {len(non)} 他人反代（官方保底 {need_official}/{TOTAL_QUOTA}）")

    # 输出国家码：机场码 → ISO 国家码（NRT/SIN/TPE 等机场码 cfnb 解析器不认）
    # "?" 桶输出裸 IP:PORT（不带 #）——main.py 的 _parse_text_nodes 会把裸行交给可用性
    # API 实测真实落地国家，这是唯一对"他人反代"有效的国家来源。
    OUT_CODE = {"NRT": "JP", "JP": "JP", "TW": "TW", "SG": "SG", "US": "US"}
    lines = [(f'{r["ip"]}:{r["port"]}' if r["region"] == UNKNOWN_REGION
              else f'{r["ip"]}:{r["port"]}#{OUT_CODE.get(r["region"], r["region"])}')
             for r in selected]

    # ---- 统计输出 ----
    from collections import Counter
    print("\n产出地区分布:", dict(Counter(r["region"] for r in selected)))
    print("产出端口分布:", dict(Counter(r["port"] for r in selected)))
    print("产出源分布:  ", dict(Counter(r["tag"] for r in selected)))

    if len(lines) < 90:
        print(f"[warn] 仅 {len(lines)}/120（源波动正常，下次运行自动补齐）")

    with io.open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n[done] 产出 {len(lines)} 个 → {OUT}")
    for l in lines:
        print("  ", l)

    # ---- 良心云保底名单（2026-09-25 用户拍板：额外 10 名额、审查放宽 30%）----
    # 从过滤后全量 dedup 里取 LX- 源候选（不参与 120 名额竞争），main.py 拿它做放宽口径的保底测量。
    LX_OUT = os.path.join(DIR, "zip_nrt_lx.txt")
    lx = [r for r in dedup.values() if str(r.get("tag", "")).startswith("LX-")]
    lx.sort(key=lambda x: (PORT_ORDER.index(x["port"]) if x["port"] in PORT_ORDER else 99))
    lx_lines = [(f'{r["ip"]}:{r["port"]}' if r["region"] == UNKNOWN_REGION
                 else f'{r["ip"]}:{r["port"]}#{OUT_CODE.get(r["region"], r["region"])}')
                for r in lx[:40]]
    try:
        with io.open(LX_OUT, "w", encoding="utf-8") as f:
            f.write("\n".join(lx_lines))
        print(f"[LX保底] 良心云候选 {len(lx_lines)}/{len(lx)} 个（上限 40）→ {LX_OUT}")
    except Exception as e:
        print(f"[LX保底] 写出失败: {e}")

    # 健康记账写回（本轮所有源/订阅器的存活计数）
    try:
        io.open(HEALTH_FILE, "w", encoding="utf-8").write(
            json.dumps(HEALTH, ensure_ascii=False, indent=1))
    except Exception as e:
        print(f"[健康] 写回失败: {e}")

if __name__ == "__main__":
    main()