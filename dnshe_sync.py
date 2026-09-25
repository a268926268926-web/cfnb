# -*- coding: utf-8 -*-
"""dnshe_sync.py — 把本轮实测优选池写进自建动态优选域名的 A 记录（DNSHE）

定位：ip.txt 是"测出来的池"，本脚本把它变成"一个域名"——客户端只要订阅里写
      cf.codm.l.cd:443，域名解析到哪台边缘由我们每轮更新，换 IP 不需要客户端重订。

只用 443 端口的条目：A 记录没有端口概念，客户端会以 `域名:443` 去连；
非 443 条目（2087/8443…）写进 A 记录会让客户端连错端口 → 必然失败，故一律排除。

用法（默认 dry-run，只打印计划不动线上；加 --apply 才写）：
  python dnshe_sync.py probe            # 只读：把 API 的原始响应打出来（第一次接钥匙用）
  python dnshe_sync.py                  # 打印本轮计划（不写）
  python dnshe_sync.py --apply          # 真的写：建缺的、删多的
  python dnshe_sync.py --apply --max 8  # 只保留前 8 条

密钥来源（绝不硬编码、绝不打印）：
  set DNSHE_KEY=cfsd_xxx   /  set DNSHE_SECRET=xxx
"""
import io, json, os, sys, urllib.request, urllib.error, urllib.parse

DIR = os.path.dirname(os.path.abspath(__file__))
IP_FILE = os.path.join(DIR, "ip.txt")
DOMAIN = os.environ.get("DNSHE_DOMAIN", "cf.codm.l.cd")
TTL = 60
API = "https://api005.dnshe.com/index.php?m=domain_hub"


def _key():
    k = os.environ.get("DNSHE_KEY", "").strip()
    s = os.environ.get("DNSHE_SECRET", "").strip()
    if not k or not s:
        print("[!] 缺 DNSHE_KEY / DNSHE_SECRET 环境变量。创建路径：my.dnshe.com → 域名管理 → "
              "左侧 API 管理 → 创建（Secret 只显示一次，请立刻存好）")
        sys.exit(2)
    return k, s


# ---- DNSHE 客户端限速（2026-09-26 实测：30 请求/窗口，域名层扩到 30 后
# 一次大换血=最多 30 建+30 删=60 次调用必撞 429；故在唯一出口处统一限速+重试）----
_RATE_TIMES = []          # 最近请求时间戳（monotonic）
RATE_MAX_CALLS = 26       # 每窗口放行数（<30 留安全余量）
RATE_WINDOW_S = 62.0      # 窗口长度（比 1 分钟稍长，保守）
RATE_429_RETRIES = 3      # 429 重试次数
RATE_429_WAIT_S = 20.0    # 429 后等待秒数

def _rate_gate():
    """滚动窗口限速：窗口内已达上限则睡到最旧请求出窗。"""
    import time as _t
    now = _t.monotonic()
    while _RATE_TIMES and now - _RATE_TIMES[0] > RATE_WINDOW_S:
        _RATE_TIMES.pop(0)
    if len(_RATE_TIMES) >= RATE_MAX_CALLS:
        wait = RATE_WINDOW_S - (now - _RATE_TIMES[0]) + 0.5
        if wait > 0:
            print(f"[限速] DNSHE 窗口内已有 {len(_RATE_TIMES)} 次调用，等待 {wait:.0f}s ...")
            _t.sleep(wait)
    import time as _t2
    _RATE_TIMES.append(_t2.monotonic())

def call(endpoint, action, body=None, timeout=25, params=None):
    """调用 DNSHE v2.0。认证走请求头（v2.0 禁止 URL/Body 传 key）。
    读接口必须 GET（2026-09-21 probe：dns_records/list 用 POST → 405 allowed GET），
    所以 params 走查询串发 GET；写接口才用 JSON body 走 POST。
    内置：客户端限速（30/窗口实测）+ 429 自动等待重试。"""
    k, s = _key()
    url = f"{API}&endpoint={endpoint}&action={action}"
    data = None
    if params:
        url += "&" + urllib.parse.urlencode(params)
    elif body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    req.add_header("X-API-Key", k)
    req.add_header("X-API-Secret", s)
    if data:
        req.add_header("Content-Type", "application/json")
    attempt = 0
    while True:
        _rate_gate()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            body_txt = e.read().decode("utf-8", "replace")
            if e.code == 429 and attempt < RATE_429_RETRIES:
                attempt += 1
                print(f"[限速] DNSHE 429（第 {attempt}/{RATE_429_RETRIES} 次重试），等 {RATE_429_WAIT_S}s ...")
                import time as _t3
                _t3.sleep(RATE_429_WAIT_S)
                continue
            return e.code, body_txt
        except Exception as e:
            return -1, f"{type(e).__name__}: {e}"


def read_pool():
    """ip.txt → 只保留 443 的 IP（去重、保序=本轮分数序）"""
    try:
        lines = [l.strip() for l in io.open(IP_FILE, encoding="utf-8") if l.strip()]
    except Exception as e:
        print(f"[!] 读不到 {IP_FILE}: {e}")
        sys.exit(2)
    out, seen = [], set()
    for l in lines:
        body = l.split("#")[0]
        if ":" not in body:
            continue
        ip, port = body.rsplit(":", 1)
        if port != "443" or ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out


def find_subdomain(fqdn):
    """在 subdomains 列表里找到 fqdn 所属的 subdomain_id 与记录名。
    DNSHE 的模型：subdomain = 你注册/托管的那个域，dns_records 的 name 是它前面的标签。"""
    code, body = call("subdomains", "list")
    if code != 200:
        print(f"[!] subdomains list 失败 HTTP {code}: {body[:200]}")
        sys.exit(3)
    try:
        data = json.loads(body)
    except Exception:
        print(f"[!] subdomains list 返回不是 JSON：{body[:300]}")
        sys.exit(3)
    items = data.get("data") or data.get("list") or data.get("subdomains") or []
    if isinstance(items, dict):
        items = items.get("list") or items.get("items") or []
    best = None
    for it in items:
        if not isinstance(it, dict):
            continue
        # DNSHE v2.0 实测字段：full_domain / subdomain / rootdomain / id（2026-09-21 probe）
        zone = str(it.get("full_domain") or it.get("domain") or it.get("name") or it.get("subdomain") or "").strip(".")
        if zone and (fqdn == zone or fqdn.endswith("." + zone)):
            if best is None or len(zone) > len(best[1]):
                best = (it.get("id") or it.get("subdomain_id"), zone)
    if not best:
        print(f"[!] 在 {len(items)} 个 subdomain 里找不到 {fqdn} 的归属。原始响应：")
        print(body[:600])
        sys.exit(3)
    sid, zone = best
    name = fqdn[: -(len(zone) + 1)] if fqdn != zone else "@"
    return sid, name, zone


def list_a(sid, name):
    code, body = call("dns_records", "list", params={"subdomain_id": sid})
    if code != 200:
        return None, f"HTTP {code}: {body[:200]}"
    try:
        data = json.loads(body)
    except Exception:
        return None, f"非 JSON: {body[:300]}"
    items = data.get("data") or data.get("list") or data.get("records") or []
    if isinstance(items, dict):
        items = items.get("list") or items.get("items") or []
    cur = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        if str(it.get("type", "")).upper() != "A":
            continue
        # 实测 API 返回的 name 是全名 cf.codm.l.cd（不是短标签），两种都认
        nm = str(it.get("name", "")).rstrip(".")
        if nm not in (name, DOMAIN):
            continue
        # 删除接口要的是 record_id（pdns_ 前缀串），数字 id 仅列表用
        rid = it.get("record_id") or it.get("id")
        if rid is not None:
            cur[str(it.get("content"))] = rid
    return cur, None


def main():
    argv = sys.argv[1:]
    if "probe" in argv:
        sid, name, zone = find_subdomain(DOMAIN)
        print(f"subdomain_id={sid} zone={zone} 记录名={name!r}")
        for ep, act, ps in (("subdomains", "list", None),
                            ("dns_records", "list", {"subdomain_id": sid})):
            c, b = call(ep, act, params=ps)
            print(f"\n--- {ep}/{act} HTTP {c} ---\n{b[:900]}")
        return

    apply_ = "--apply" in argv
    maxn = 30        # 域名层容量：主池 30 个 443 全进域名（9/26 起 20→30；非 443 端口节点与 #LX 保底才留在外溢层；create 失败由写后回读保护兜底）
    if "--max" in argv:
        maxn = int(argv[argv.index("--max") + 1])

    want = read_pool()[:maxn]
    if not want:
        print("[!] ip.txt 里没有 443 的条目，无可同步（不动线上）")
        sys.exit(1)

    sid, name, zone = find_subdomain(DOMAIN)
    print(f"目标 {DOMAIN} → subdomain_id={sid} zone={zone} name={name!r} TTL={TTL}")
    cur, err = list_a(sid, name)
    if cur is None:
        print(f"[!] 读现有 A 记录失败：{err}")
        print("    若是 action/字段名不对，先跑 `python dnshe_sync.py probe` 看原始响应")
        sys.exit(3)

    add = [ip for ip in want if ip not in cur]
    dele = [ip for ip in cur if ip not in want]
    print(f"\n本轮池(443) {len(want)} 条 | 现有 A 记录 {len(cur)} 条")
    print(f"  需新增 {len(add)}: {add}")
    print(f"  需删除 {len(dele)}: {dele}")
    if not add and not dele:
        print("\n[=] 已一致，无需改动")
        return
    if not apply_:
        print("\n[dry-run] 未写入。确认无误后加 --apply 执行")
        return

    ok = True
    for ip in add:
        c, b = call("dns_records", "create",
                    {"subdomain_id": sid, "type": "A", "name": name,
                     "content": ip, "ttl": TTL})
        print(f"  + {ip} -> HTTP {c} {b[:120]}")
        ok = ok and c == 200
    if not ok:
        print("[!] 新增记录失败，保留全部旧记录；本轮不执行删除")
        sys.exit(1)

    # API 返回成功不等于记录已经可见；确认新池齐全后才能删除旧池。
    # 这一步也拦住 HTTP 200 但业务失败、配额不足或短暂一致性延迟。
    import time
    if add:
        confirmed, confirm_error = list_a(sid, name)
        for _ in range(3):
            if confirmed is not None and all(ip in confirmed for ip in want):
                break
            time.sleep(4)
            confirmed, confirm_error = list_a(sid, name)
        if confirmed is None or not all(ip in confirmed for ip in want):
            print("[!] 新记录未完整回读确认，保留全部旧记录；本轮不执行删除")
            sys.exit(1)

    for ip in dele:
        c, b = call("dns_records", "delete",
                    {"subdomain_id": sid, "record_id": cur[ip]})
        print(f"  - {ip} -> HTTP {c} {b[:120]}")
        ok = ok and c == 200

    cur2, err2 = list_a(sid, name)
    for _ in range(3):
        if cur2 is not None and set(cur2) == set(want):
            break
        # API 有最终一致性延迟：create 全 200 后 list 仍可能短暂回旧值（2026-09-21 实测）
        time.sleep(4)
        cur2, err2 = list_a(sid, name)
    if cur2 is None:
        print(f"[!] 写后回读失败：{err2}")
        sys.exit(3)
    print(f"\n[回读] {DOMAIN} 现有 A 记录 {len(cur2)} 条：{sorted(cur2)}")
    missing = [ip for ip in want if ip not in cur2]
    if missing:
        print(f"[!] 仍有 {len(missing)} 条未生效：{missing}")
        ok = False
    extra = [ip for ip in cur2 if ip not in want]
    if extra:
        print(f"[!] 仍有 {len(extra)} 条旧记录未移除：{extra}")
        ok = False
    print("[done] 同步完成" if ok else "[done] 部分失败，见上")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
