# -*- coding: utf-8 -*-
"""push_api.py — 用 GitHub Contents API 推 ip.txt（绕过大陆被墙的 github.com:443）
背景：2026-09-16 实测直连下 github.com:443 超时不可达，而 api.github.com 200/0.75s、
raw.githubusercontent.com 也通 → git push 死路，Contents API 活路。
凭据不复制：从同目录 git_sync.ps1 里解析 $github_token / $github_username / $repo_name / $branch。
用法: python push_api.py [文件] [--check]   (默认 ip.txt；--check 只读比较)
"""
import argparse, base64, hashlib, io, json, os, re, sys, urllib.error, urllib.request, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
SYNC = os.path.join(HERE, "git_sync.ps1")


def read_creds():
    with io.open(SYNC, encoding="utf-8", errors="ignore") as source:
        txt = source.read()
    def grab(name, default=None):
        m = re.search(r'\$' + name + r'\s*=\s*"([^"]+)"', txt)
        return m.group(1) if m else default
    tok = grab("github_token")
    user = grab("github_username")
    repo = grab("repo_name")
    br = grab("branch", "main")
    if not all((tok, user, repo)):
        raise SystemExit("无法从 git_sync.ps1 解析出 token/用户名/仓库名")
    return tok, user, repo, br


def api(url, tok, method="GET", payload=None):
    data = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {tok}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "cfnb-push-api")
    req.add_header("Cache-Control", "no-cache")
    if data:
        req.add_header("Content-Type", "application/json")
    # 发布路径固定直连：git 回退遗留的 HTTP(S)_PROXY 曾让 API 同步也连死端口。
    # 只影响本请求，不修改用户环境、系统代理或 sing-box。
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=30) as r:
        return r.status, json.loads(r.read().decode("utf-8", "ignore") or "{}")


def main():
    parser = argparse.ArgumentParser(description="同步优选池到 GitHub Contents API")
    parser.add_argument("file", nargs="?", default="ip.txt")
    parser.add_argument("--check", action="store_true", help="只读比较，不发布")
    args = parser.parse_args()
    path = os.path.join(HERE, args.file)
    fname = os.path.basename(path)
    with open(path, "rb") as source:
        content = source.read()
    if not content.strip():
        print("[push_api] 空文件，拒绝覆盖远端")
        return 1
    local_sha = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
    tok, user, repo, br = read_creds()
    base = f"https://api.github.com/repos/{user}/{repo}/contents/{urllib.parse.quote(fname, safe='')}"
    read_url = f"{base}?ref={urllib.parse.quote(br, safe='')}"
    sha = None
    try:
        _, cur = api(read_url, tok)
        sha = cur.get("sha")
        if sha == local_sha:
            print(f"[push_api] 已回读：本地与远端相同，无需提交；nodes={len(content.splitlines())}")
            return 0
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print(f"[push_api] 读取远端失败：HTTP {e.code}")
            return 1
    except Exception as e:
        # 连不上 api.github.com 时不能瞎猜 sha：没有 sha 的 PUT 会被 GitHub 当新建→409
        print(f"[push_api] 读取远端 sha 失败（网络问题？本轮放弃，下轮重试）：{e}")
        return 1
    if args.check:
        print(f"[push_api] 只读检查：本地与远端不同；local={local_sha[:8]} remote={(sha or 'missing')[:8]}")
        return 2
    payload = {
        "message": f"cfnb: direct-link round update {fname}",
        "content": base64.b64encode(content).decode(),
        "branch": br,
    }
    if sha:
        payload["sha"] = sha
    try:
        code, res = api(base, tok, method="PUT", payload=payload)
        _, verified = api(read_url, tok)
        if verified.get("sha") != local_sha:
            print("[push_api] 提交后回读不一致，本轮报告失败；下一轮按最新 SHA 重试")
            return 1
        print(f"[push_api] OK {code} commit={res.get('commit', {}).get('sha', '')[:8]} "
              f"nodes={len(content.strip().splitlines())} via api.github.com，内容回读一致")
        return 0
    except urllib.error.HTTPError as e:
        print(f"[push_api] 失败：HTTP {e.code}")
        return 1
    except Exception as e:
        print(f"[push_api] 失败：{e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
