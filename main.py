#!/usr/bin/env python3
"""
Cloudflare IP 优选工具 (TCP筛选 + IP可用性二次筛选 + HTTP检测 + curl带宽测速 + WxPusher通知)
依赖：requests, curl, aiohttp
配置文件：同目录下的 config.json
结果保存到 ip.txt，并自动推送到 GitHub，同时批量更新到 Cloudflare DNS
支持 Windows / Linux
"""

import requests
import socket
import time
import sys
import re
import os
import subprocess
import shutil
import json
import asyncio
import aiohttp
import ipaddress
import argparse
import math
import tempfile
from urllib.parse import urlsplit
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning

# 修复 Windows 下 ProactorEventLoop 残留任务报警
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# 禁用 SSL 警告 (用于 HTTP 检测)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ===== 全局禁用 SSL 验证（解决证书问题）=====
import functools
original_get = requests.get
original_post = requests.post

def new_get(url, *args, **kwargs):
    kwargs.setdefault('verify', False)
    return original_get(url, *args, **kwargs)

def new_post(url, *args, **kwargs):
    kwargs.setdefault('verify', False)
    return original_post(url, *args, **kwargs)

requests.get = new_get
requests.post = new_post
# ===========================================

# ==================== 预编译正则 ====================
NODE_PATTERN = re.compile(r"^(\d+\.\d+\.\d+\.\d+):(\d+)#(.+)$")
IP_PORT_PATTERN = re.compile(r"^(\d+\.\d+\.\d+\.\d+):(\d+)#")

# ==================== 国家代码映射表（全球覆盖）====================
CN_TO_CODE = {
    "阿富汗": "AF", "奥兰群岛": "AX", "阿尔巴尼亚": "AL", "阿尔及利亚": "DZ",
    "美属萨摩亚": "AS", "安道尔": "AD", "安哥拉": "AO", "安圭拉": "AI",
    "南极洲": "AQ", "安提瓜和巴布达": "AG", "阿根廷": "AR", "亚美尼亚": "AM",
    "阿鲁巴": "AW", "澳大利亚": "AU", "奥地利": "AT", "阿塞拜疆": "AZ",
    "巴哈马": "BS", "巴林": "BH", "孟加拉国": "BD", "孟加拉": "BD",
    "巴巴多斯": "BB", "白俄罗斯": "BY", "比利时": "BE", "伯利兹": "BZ",
    "贝宁": "BJ", "百慕大": "BM", "不丹": "BT", "玻利维亚": "BO",
    "波黑": "BA", "波斯尼亚和黑塞哥维那": "BA", "博茨瓦纳": "BW",
    "布维岛": "BV", "巴西": "BR", "英属印度洋领地": "IO",
    "文莱": "BN", "保加利亚": "BG", "布基纳法索": "BF", "布隆迪": "BI",
    "柬埔寨": "KH", "喀麦隆": "CM", "加拿大": "CA", "佛得角": "CV",
    "开曼群岛": "KY", "中非": "CF", "乍得": "TD", "智利": "CL",
    "中国": "CN", "圣诞岛": "CX", "科科斯(基林)群岛": "CC",
    "哥伦比亚": "CO", "科摩罗": "KM", "刚果(布)": "CG", "刚果（布）": "CG",
    "刚果(金)": "CD", "刚果（金）": "CD", "库克群岛": "CK",
    "哥斯达黎加": "CR", "科特迪瓦": "CI", "克罗地亚": "HR", "古巴": "CU",
    "塞浦路斯": "CY", "捷克": "CZ", "丹麦": "DK", "吉布提": "DJ",
    "多米尼克": "DM", "多米尼加": "DO", "厄瓜多尔": "EC", "埃及": "EG",
    "萨尔瓦多": "SV", "赤道几内亚": "GQ", "厄立特里亚": "ER",
    "爱沙尼亚": "EE", "埃塞俄比亚": "ET", "福克兰群岛(马尔维纳斯)": "FK",
    "法罗群岛": "FO", "斐济": "FJ", "芬兰": "FI", "法国": "FR",
    "法属圭亚那": "GF", "法属波利尼西亚": "PF", "法属南部领地": "TF",
    "加蓬": "GA", "冈比亚": "GM", "格鲁吉亚": "GE", "德国": "DE",
    "加纳": "GH", "直布罗陀": "GI", "希腊": "GR", "格陵兰": "GL",
    "格林纳达": "GD", "瓜德罗普": "GP", "关岛": "GU", "危地马拉": "GT",
    "根西岛": "GG", "几内亚": "GN", "几内亚比绍": "GW", "圭亚那": "GY",
    "海地": "HT", "赫德岛和麦克唐纳群岛": "HM", "梵蒂冈": "VA",
    "洪都拉斯": "HN", "香港": "HK", "匈牙利": "HU", "冰岛": "IS",
    "印度": "IN", "印度尼西亚": "ID", "伊朗": "IR", "伊拉克": "IQ",
    "爱尔兰": "IE", "马恩岛": "IM", "以色列": "IL", "意大利": "IT",
    "牙买加": "JM", "日本": "JP", "泽西岛": "JE", "约旦": "JO",
    "哈萨克斯坦": "KZ", "肯尼亚": "KE", "基里巴斯": "KI", "朝鲜": "KP",
    "韩国": "KR", "科威特": "KW", "吉尔吉斯斯坦": "KG", "老挝": "LA",
    "拉脱维亚": "LV", "黎巴嫩": "LB", "莱索托": "LS", "利比里亚": "LR",
    "利比亚": "LY", "列支敦士登": "LI", "立陶宛": "LT", "卢森堡": "LU",
    "澳门": "MO", "北马其顿": "MK", "马其顿": "MK", "马达加斯加": "MG",
    "马拉维": "MW", "马来西亚": "MY", "马尔代夫": "MV", "马里": "ML",
    "马耳他": "MT", "马绍尔群岛": "MH", "马提尼克": "MQ",
    "毛里塔尼亚": "MR", "毛里求斯": "MU", "马约特": "YT", "墨西哥": "MX",
    "密克罗尼西亚": "FM", "摩尔多瓦": "MD", "摩纳哥": "MC", "蒙古": "MN",
    "黑山": "ME", "蒙特塞拉特": "MS", "摩洛哥": "MA", "莫桑比克": "MZ",
    "缅甸": "MM", "纳米比亚": "NA", "瑙鲁": "NR", "尼泊尔": "NP",
    "荷兰": "NL", "新喀里多尼亚": "NC", "新西兰": "NZ", "尼加拉瓜": "NI",
    "尼日尔": "NE", "尼日利亚": "NG", "纽埃": "NU", "诺福克岛": "NF",
    "北马里亚纳群岛": "MP", "挪威": "NO", "阿曼": "OM", "巴基斯坦": "PK",
    "帕劳": "PW", "巴勒斯坦": "PS", "巴拿马": "PA", "巴布亚新几内亚": "PG",
    "巴拉圭": "PY", "秘鲁": "PE", "菲律宾": "PH", "皮特凯恩": "PN",
    "波兰": "PL", "葡萄牙": "PT", "波多黎各": "PR", "卡塔尔": "QA",
    "留尼汪": "RE", "罗马尼亚": "RO", "俄罗斯": "RU", "卢旺达": "RW",
    "圣巴泰勒米": "BL", "圣赫勒拿": "SH", "圣基茨和尼维斯": "KN",
    "圣卢西亚": "LC", "圣马丁": "MF", "圣皮埃尔和密克隆": "PM",
    "圣文森特和格林纳丁斯": "VC", "萨摩亚": "WS", "圣马力诺": "SM",
    "圣多美和普林西比": "ST", "沙特阿拉伯": "SA", "沙特": "SA",
    "塞内加尔": "SN", "塞尔维亚": "RS", "塞舌尔": "SC", "塞拉利昂": "SL",
    "新加坡": "SG", "圣马丁(荷兰)": "SX", "斯洛伐克": "SK",
    "斯洛文尼亚": "SI", "所罗门群岛": "SB", "索马里": "SO", "南非": "ZA",
    "南乔治亚和南桑威奇群岛": "GS", "南苏丹": "SS", "西班牙": "ES",
    "斯里兰卡": "LK", "苏丹": "SD", "苏里南": "SR", "斯瓦尔巴和扬马延": "SJ",
    "斯威士兰": "SZ", "瑞典": "SE", "瑞士": "CH", "叙利亚": "SY",
    "台湾": "TW", "塔吉克斯坦": "TJ", "坦桑尼亚": "TZ", "泰国": "TH",
    "东帝汶": "TL", "多哥": "TG", "托克劳": "TK", "汤加": "TO",
    "特立尼达和多巴哥": "TT", "突尼斯": "TN", "土耳其": "TR",
    "土库曼斯坦": "TM", "特克斯和凯科斯群岛": "TC", "图瓦卢": "TV",
    "乌干达": "UG", "乌克兰": "UA", "阿联酋": "AE", "英国": "GB",
    "美国": "US", "美国本土外小岛屿": "UM", "乌拉圭": "UY",
    "乌兹别克斯坦": "UZ", "瓦努阿图": "VU", "委内瑞拉": "VE",
    "越南": "VN", "英属维尔京群岛": "VG", "美属维尔京群岛": "VI",
    "瓦利斯和富图纳": "WF", "西撒哈拉": "EH", "也门": "YE",
    "赞比亚": "ZM", "津巴布韦": "ZW",
}

# 三位字母国家代码 → 两位字母国家代码（ISO 3166-1 alpha-3 → alpha-2）
ALPHA3_TO_ALPHA2 = {
    "AFG": "AF", "ALA": "AX", "ALB": "AL", "DZA": "DZ", "ASM": "AS",
    "AND": "AD", "AGO": "AO", "AIA": "AI", "ATA": "AQ", "ATG": "AG",
    "ARG": "AR", "ARM": "AM", "ABW": "AW", "AUS": "AU", "AUT": "AT",
    "AZE": "AZ", "BHS": "BS", "BHR": "BH", "BGD": "BD", "BRB": "BB",
    "BLR": "BY", "BEL": "BE", "BLZ": "BZ", "BEN": "BJ", "BMU": "BM",
    "BTN": "BT", "BOL": "BO", "BIH": "BA", "BWA": "BW", "BVT": "BV",
    "BRA": "BR", "IOT": "IO", "BRN": "BN", "BGR": "BG", "BFA": "BF",
    "BDI": "BI", "KHM": "KH", "CMR": "CM", "CAN": "CA", "CPV": "CV",
    "CYM": "KY", "CAF": "CF", "TCD": "TD", "CHL": "CL", "CHN": "CN",
    "CXR": "CX", "CCK": "CC", "COL": "CO", "COM": "KM", "COG": "CG",
    "COD": "CD", "COK": "CK", "CRI": "CR", "CIV": "CI", "HRV": "HR",
    "CUB": "CU", "CYP": "CY", "CZE": "CZ", "DNK": "DK", "DJI": "DJ",
    "DMA": "DM", "DOM": "DO", "ECU": "EC", "EGY": "EG", "SLV": "SV",
    "GNQ": "GQ", "ERI": "ER", "EST": "EE", "ETH": "ET", "FLK": "FK",
    "FRO": "FO", "FJI": "FJ", "FIN": "FI", "FRA": "FR", "GUF": "GF",
    "PYF": "PF", "ATF": "TF", "GAB": "GA", "GMB": "GM", "GEO": "GE",
    "DEU": "DE", "GHA": "GH", "GIB": "GI", "GRC": "GR", "GRL": "GL",
    "GRD": "GD", "GLP": "GP", "GUM": "GU", "GTM": "GT", "GGY": "GG",
    "GIN": "GN", "GNB": "GW", "GUY": "GY", "HTI": "HT", "HMD": "HM",
    "VAT": "VA", "HND": "HN", "HKG": "HK", "HUN": "HU", "ISL": "IS",
    "IND": "IN", "IDN": "ID", "IRN": "IR", "IRQ": "IQ", "IRL": "IE",
    "IMN": "IM", "ISR": "IL", "ITA": "IT", "JAM": "JM", "JPN": "JP",
    "JEY": "JE", "JOR": "JO", "KAZ": "KZ", "KEN": "KE", "KIR": "KI",
    "PRK": "KP", "KOR": "KR", "KWT": "KW", "KGZ": "KG", "LAO": "LA",
    "LVA": "LV", "LBN": "LB", "LSO": "LS", "LBR": "LR", "LBY": "LY",
    "LIE": "LI", "LTU": "LT", "LUX": "LU", "MAC": "MO", "MKD": "MK",
    "MDG": "MG", "MWI": "MW", "MYS": "MY", "MDV": "MV", "MLI": "ML",
    "MLT": "MT", "MHL": "MH", "MTQ": "MQ", "MRT": "MR", "MUS": "MU",
    "MYT": "YT", "MEX": "MX", "FSM": "FM", "MDA": "MD", "MCO": "MC",
    "MNG": "MN", "MNE": "ME", "MSR": "MS", "MAR": "MA", "MOZ": "MZ",
    "MMR": "MM", "NAM": "NA", "NRU": "NR", "NPL": "NP", "NLD": "NL",
    "NCL": "NC", "NZL": "NZ", "NIC": "NI", "NER": "NE", "NGA": "NG",
    "NIU": "NU", "NFK": "NF", "MNP": "MP", "NOR": "NO", "OMN": "OM",
    "PAK": "PK", "PLW": "PW", "PSE": "PS", "PAN": "PA", "PNG": "PG",
    "PRY": "PY", "PER": "PE", "PHL": "PH", "PCN": "PN", "POL": "PL",
    "PRT": "PT", "PRI": "PR", "QAT": "QA", "REU": "RE", "ROU": "RO",
    "RUS": "RU", "RWA": "RW", "BLM": "BL", "SHN": "SH", "KNA": "KN",
    "LCA": "LC", "MAF": "MF", "SPM": "PM", "VCT": "VC", "WSM": "WS",
    "SMR": "SM", "STP": "ST", "SAU": "SA", "SEN": "SN", "SRB": "RS",
    "SYC": "SC", "SLE": "SL", "SGP": "SG", "SXM": "SX", "SVK": "SK",
    "SVN": "SI", "SLB": "SB", "SOM": "SO", "ZAF": "ZA", "SGS": "GS",
    "SSD": "SS", "ESP": "ES", "LKA": "LK", "SDN": "SD", "SUR": "SR",
    "SJM": "SJ", "SWZ": "SZ", "SWE": "SE", "CHE": "CH", "SYR": "SY",
    "TWN": "TW", "TJK": "TJ", "TZA": "TZ", "THA": "TH", "TLS": "TL",
    "TGO": "TG", "TKL": "TK", "TON": "TO", "TTO": "TT", "TUN": "TN",
    "TUR": "TR", "TKM": "TM", "TCA": "TC", "TUV": "TV", "UGA": "UG",
    "UKR": "UA", "ARE": "AE", "GBR": "GB", "USA": "US", "UMI": "UM",
    "URY": "UY", "UZB": "UZ", "VUT": "VU", "VEN": "VE", "VNM": "VN",
    "VGB": "VG", "VIR": "VI", "WLF": "WF", "ESH": "EH", "YEM": "YE",
    "ZMB": "ZM", "ZWE": "ZW",
}

# 构建两位有效代码集合，用于快速校验
CODE_SET = set(CN_TO_CODE.values())


# ==================== 加载配置文件 ====================
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

def load_config():
    """加载 config.json 配置文件，缺失必填字段时抛出异常"""
    defaults = {
        "USE_GLOBAL_MODE": True,
        "GLOBAL_TOP_N": 15,
        "PER_COUNTRY_TOP_N": 1,
        "BANDWIDTH_CANDIDATES": 150,
        "TCP_PROBES": 3,# 探测次数（2026-09-18：从 1→3，抗 flash-in-the-pan）
        "TCP_AGGREGATION": "median",# 'min'/'median'; median 抗瞬间快但挂的 IP
        "STABILITY_WINDOW": 4,# 历史窗口轮数（近 N 轮）
        "STABILITY_BONUS": 0.0,# 2026-09-18 用户质疑站岗轮换后全关（config 亦为 0）——纯排名
        "INCUMBENT_RATIO": 0.0,# 在岗优先硬保位比例（0=关闭；2026-09-18 用户质疑后关掉，config 亦为 0）
        "CF_OFFICIAL_RATIO": 0.0,# 最终池是否强制"官方段:他人反代"配比；0=不强制，纯分数前 N
                                  #（2026-09-18 用户定：官方段实测就是分高，让分数自己裁决）
        "MIN_POOL_NODES": 5,# 池子小于此数则拒绝覆盖 ip.txt / 拒绝推送（防 0 节点事故）
        "MIN_SUCCESS_RATE": 1.0,
        "TCP_LATENCY_WEIGHT": 0.0,
        "TIMEOUT": 2.0,
        "SOCKET_DEFAULT_TIMEOUT": 3,
        "PROGRESS_PRINT_INTERVAL": 1,
        "FILTER_COUNTRIES_ENABLED": False,
        "ALLOWED_COUNTRIES": ["US"],
        "PRE_FILTER_BLOCKED_ENABLED": True,
        "PRE_FILTER_BLOCKED_COUNTRIES": ["CN"],
        "PRE_FILTER_PORT_ENABLED": True,
        "PRE_FILTER_PORTS": [443],
        "ENABLE_WXPUSHER": True,
        "WXPUSHER_APP_TOKEN": "your_app_token_here",
        "WXPUSHER_UIDS": ["your_uid_here"],
        "WXPUSHER_API_URL": "https://wxpusher.zjiecode.com/api/send/message",
        "NOTIFY_TIMEOUT": 3,
        "NOTIFY_CONNECT_TIMEOUT": 3,
        "CF_ENABLED": True,
        "CF_API_TOKEN": "your_CF_API_TOKEN",
        "CF_ZONE_ID": "your_CF_ZONE_ID",
        "CF_DNS_RECORD_NAME": "your_CF_DNS_RECORD_NAME",
        "CF_TTL": 60,
        "CF_PROXIED": False,
        "CF_DNS_CONNECT_TIMEOUT": 3,
        "CF_DNS_READ_TIMEOUT": 3,
        "DNS_RECORD_TYPE": "TXT",
        "ADDITIONAL_SOURCES": [
    {
        "url": "https://zip.cm.edu.kg/all.txt",
        "enabled": True
    },
    {
        "url": "https://countrymerge.pages.dev/all.txt",
        "enabled": True
    }
],
        "FETCH_MAX_RETRIES": 3,
        "FETCH_RETRY_DELAY": 3,
        "FETCH_TIMEOUT": 3,
        "FETCH_CONNECT_TIMEOUT": 3,
        "IP_CALIBRATION_ENABLED": False,
        "TOKEN_FAILURE_THRESHOLD": 1,
        "IP_CALIBRATION_MIN_INTERVAL": 0.1,
        "IP_CALIBRATION_TOKEN_FILE": "valid_tokens.txt",
        "IP_CALIBRATION_CACHE_FILE": "ipinfo_cache.txt",
        "OUTPUT_FILE": "ip.txt",
        "ENABLE_LOGGING": False,
        "LOG_FILE": "cfnb.log",
        "FORCE_DIRECT": False,
        "TEST_AVAILABILITY": True,
        "AVAILABILITY_CHECK_API": "https://api.090227.xyz/check",
        "AVAILABILITY_TIMEOUT": 3,
        "AVAILABILITY_CONNECT_TIMEOUT": 3,
        "AVAILABILITY_RETRY_MAX": 2,
        "AVAILABILITY_RETRY_DELAY": 3,
        "AVAILABILITY_INNER_RETRY_ENABLED": True,
        "AVAILABILITY_INNER_RETRY_MAX": 2,
        "AVAILABILITY_INNER_RETRY_DELAY": 3,
        "HTTP_TEST_ENABLED": True,
        "HTTP_TEST_TIMEOUT": 3,
        "HTTP_TEST_CONNECT_TIMEOUT": 3,
        "HTTP_TEST_MAX_ROUNDS": 2,
        "HTTP_TEST_ROUND_DELAY": 3,
        "HTTP_TEST_INNER_RETRY_ENABLED": True,
        "HTTP_TEST_MAX_RETRIES": 2,
        "HTTP_TEST_RETRY_DELAY": 3,
        "HTTP_TEST_METHOD": "HEAD",
        "HTTP_LATENCY_WEIGHT": 3.0,
        "JITTER_WEIGHT": 3.0,
        "HTTP_JITTER_SAMPLES": 3,
        "FILTER_IPV6_AVAILABILITY": True,
        "FILTER_BLOCKED_COUNTRIES_ENABLED": True,
        "BLOCKED_COUNTRIES": [
            "BD", "BI", "BY", "CD", "CF", "CN", "CU", "DE", "ET", "HK",
            "IR", "KP", "LY", "MO", "NG", "NL", "PK", "RU", "SD", "SO",
            "SY", "TH", "TW", "UA", "VE", "VN", "YE", "ZW"
        ],
        "DNS_IP_RISK_FILTER_ENABLED": False,
        "DNS_IP_RISK_MAX_LEVEL": "高风险",
        "DNS_UPDATE_TARGET_COUNT": 15,
        "BANDWIDTH_SIZE_MB": 1.0,
        "BANDWIDTH_TIMEOUT": 3,
        "BANDWIDTH_RETRY_MAX": 2,
        "BANDWIDTH_RETRY_DELAY": 3,
        "BANDWIDTH_URL_TEMPLATE": "{scheme}://speed.cloudflare.com:{port}/__down?bytes={bytes}",
        # TLS 建链总耗时门槛（秒，curl time_appconnect 含 TCP）：超过则淘汰；0=关闭。
        # 依据：2026-09-16 实测量出 CM 电信优选那批 IP 握手 0.5–1.9s（电信对 CF 段恶化），
        # 而原评分只算传输速率，握手慢的节点照样入选 → 体感差。直连重跑一轮后按实况调。
        "TLS_HANDSHAKE_MAX_S": 2.0,
        "BANDWIDTH_PROCESS_BUFFER": 2,
        "BANDWIDTH_CONNECT_TIMEOUT": 3,
        "SPEED_WEIGHT": 3.0,
        # 最终排序口径（2026-09-18 用户定：速度 60% / 延迟 40%；延迟 = TCP + TLS 握手）
        # 旧公式 score=(SPEED_WEIGHT*speed)/penalty 在 HTTP 检测关闭时 penalty 恒为常数，
        # 且 TCP_LATENCY_WEIGHT=0 → 实际是"纯按速度排"，慢延迟节点照样入选。
        "SCORE_SPEED_WEIGHT": 0.6,
        "SCORE_LATENCY_WEIGHT": 0.4,
        # 最终节点 TCP 延迟硬门槛（毫秒）：超过则淘汰；0=关闭。无合格新池时保留旧池，不放宽门槛。
        "MAX_TCP_LATENCY_MS": 200,
        # 地区备胎保底（2026-09-16 用户定）：50/50 加权后日本会压倒性胜出，
        # 最终池全是 JP = 日本段一旦被 Q 就全灭。此值 = 每个"非主流地区"至少保留几个节点。
        # 0 = 关闭。仅在全局模式生效。
        "REGION_RESERVE_N": 3,
        "IP_CALIBRATION_CONCURRENCY": 300,
        "MAX_WORKERS": 300,
        "AVAILABILITY_WORKERS": 32,
        "FALLBACK_WORKERS": 32,
        "BANDWIDTH_WORKERS": 3,
        "HTTP_TEST_WORKERS": 32,
        "DNS_UPDATE_MAX_RETRIES": 3,
        "DNS_UPDATE_RETRY_DELAY": 3,
        "GITHUB_SYNC_MAX_RETRIES": 3,
        "GITHUB_SYNC_RETRY_DELAY": 3,
        "GIT_SYNC_PROCESS_TIMEOUT": 180,
        "AD_HEADER_ENABLED": False,
        "AD_HEADER_LINES": [],
        "AD_FOOTER_ENABLED": False,
        "AD_FOOTER_LINES": [],
        "AD_PERLINE_ENABLED": False,
        "AD_PERLINE_TEXT": "",
        "IP_TXT_SHOW_BANDWIDTH": False,
        "IP_TXT_SHOW_HTTP_LATENCY": False,
        "IP_TXT_SHOW_HTTP_JITTER": False,
        "IP_TXT_SHOW_LATENCY": False,
    }

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"未找到配置文件 {CONFIG_FILE}，将使用内置默认配置运行。")
        print(f"你可根据需要创建 config.json 文件（参考文档），程序会自动识别。")
        return defaults
    except json.JSONDecodeError as e:
        print(f"错误：配置文件格式不正确 - {e}")
        sys.exit(1)

    for key, value in defaults.items():
        if key not in config:
            config[key] = value
            print(f"配置项 {key} 未设置，使用默认值：{value}")

    return config

cfg = load_config()
USE_GLOBAL_MODE = cfg["USE_GLOBAL_MODE"]
GLOBAL_TOP_N = cfg["GLOBAL_TOP_N"]
PER_COUNTRY_TOP_N = cfg["PER_COUNTRY_TOP_N"]
BANDWIDTH_CANDIDATES = cfg["BANDWIDTH_CANDIDATES"]
TCP_PROBES = cfg["TCP_PROBES"]
TCP_AGGREGATION = cfg.get("TCP_AGGREGATION", "median")
STABILITY_WINDOW = int(cfg.get("STABILITY_WINDOW", 0) or 0)
STABILITY_BONUS = float(cfg.get("STABILITY_BONUS", 0.0) or 0.0)
INCUMBENT_RATIO = float(cfg.get("INCUMBENT_RATIO", 0.0) or 0.0)
CF_OFFICIAL_RATIO = float(cfg.get("CF_OFFICIAL_RATIO", 0.0))
MIN_POOL_NODES = int(cfg.get("MIN_POOL_NODES", 5) or 5)
MIN_SUCCESS_RATE = cfg["MIN_SUCCESS_RATE"]
TCP_LATENCY_WEIGHT = cfg["TCP_LATENCY_WEIGHT"]
TIMEOUT = cfg["TIMEOUT"]
SOCKET_DEFAULT_TIMEOUT = cfg["SOCKET_DEFAULT_TIMEOUT"]
PROGRESS_PRINT_INTERVAL = cfg["PROGRESS_PRINT_INTERVAL"]
FILTER_COUNTRIES_ENABLED = cfg["FILTER_COUNTRIES_ENABLED"]
ALLOWED_COUNTRIES = cfg["ALLOWED_COUNTRIES"]
PRE_FILTER_BLOCKED_ENABLED = cfg["PRE_FILTER_BLOCKED_ENABLED"]
PRE_FILTER_BLOCKED_COUNTRIES = [c.upper() for c in cfg["PRE_FILTER_BLOCKED_COUNTRIES"]]
PRE_FILTER_PORT_ENABLED = cfg["PRE_FILTER_PORT_ENABLED"]
PRE_FILTER_PORTS = [str(p) for p in cfg["PRE_FILTER_PORTS"]]
ENABLE_WXPUSHER = cfg["ENABLE_WXPUSHER"]
WXPUSHER_APP_TOKEN = cfg["WXPUSHER_APP_TOKEN"]
WXPUSHER_UIDS = cfg["WXPUSHER_UIDS"]
WXPUSHER_API_URL = cfg["WXPUSHER_API_URL"]
NOTIFY_TIMEOUT = cfg["NOTIFY_TIMEOUT"]
NOTIFY_CONNECT_TIMEOUT = cfg["NOTIFY_CONNECT_TIMEOUT"]
CF_ENABLED = cfg["CF_ENABLED"]
CF_API_TOKEN = cfg["CF_API_TOKEN"]
CF_ZONE_ID = cfg["CF_ZONE_ID"]
CF_DNS_RECORD_NAME = cfg["CF_DNS_RECORD_NAME"]
CF_TTL = cfg["CF_TTL"]
CF_PROXIED = cfg["CF_PROXIED"]
CF_DNS_CONNECT_TIMEOUT = cfg["CF_DNS_CONNECT_TIMEOUT"]
CF_DNS_READ_TIMEOUT = cfg["CF_DNS_READ_TIMEOUT"]
DNS_RECORD_TYPE = cfg["DNS_RECORD_TYPE"]
ADDITIONAL_SOURCES = cfg["ADDITIONAL_SOURCES"]
FETCH_MAX_RETRIES = cfg["FETCH_MAX_RETRIES"]
FETCH_RETRY_DELAY = cfg["FETCH_RETRY_DELAY"]
FETCH_TIMEOUT = cfg["FETCH_TIMEOUT"]
FETCH_CONNECT_TIMEOUT = cfg["FETCH_CONNECT_TIMEOUT"]
IP_CALIBRATION_ENABLED = cfg["IP_CALIBRATION_ENABLED"]
TOKEN_FAILURE_THRESHOLD = cfg["TOKEN_FAILURE_THRESHOLD"]
IP_CALIBRATION_MIN_INTERVAL = cfg["IP_CALIBRATION_MIN_INTERVAL"]
IP_CALIBRATION_TOKEN_FILE = cfg["IP_CALIBRATION_TOKEN_FILE"]
IP_CALIBRATION_CACHE_FILE = cfg["IP_CALIBRATION_CACHE_FILE"]
OUTPUT_FILE = cfg["OUTPUT_FILE"]
ENABLE_LOGGING = cfg["ENABLE_LOGGING"]
LOG_FILE = cfg["LOG_FILE"]
FORCE_DIRECT = cfg["FORCE_DIRECT"]
TEST_AVAILABILITY = cfg["TEST_AVAILABILITY"]
AVAILABILITY_CHECK_API = cfg["AVAILABILITY_CHECK_API"]
AVAILABILITY_TIMEOUT = cfg["AVAILABILITY_TIMEOUT"]
AVAILABILITY_CONNECT_TIMEOUT = cfg["AVAILABILITY_CONNECT_TIMEOUT"]
AVAILABILITY_RETRY_MAX = cfg["AVAILABILITY_RETRY_MAX"]
AVAILABILITY_RETRY_DELAY = cfg["AVAILABILITY_RETRY_DELAY"]
AVAILABILITY_INNER_RETRY_ENABLED = cfg["AVAILABILITY_INNER_RETRY_ENABLED"]
AVAILABILITY_INNER_RETRY_MAX = cfg["AVAILABILITY_INNER_RETRY_MAX"]
AVAILABILITY_INNER_RETRY_DELAY = cfg["AVAILABILITY_INNER_RETRY_DELAY"]
HTTP_TEST_ENABLED = cfg["HTTP_TEST_ENABLED"]
HTTP_TEST_TIMEOUT = cfg["HTTP_TEST_TIMEOUT"]
HTTP_TEST_CONNECT_TIMEOUT = cfg["HTTP_TEST_CONNECT_TIMEOUT"]
HTTP_TEST_MAX_ROUNDS = cfg["HTTP_TEST_MAX_ROUNDS"]
HTTP_TEST_ROUND_DELAY = cfg["HTTP_TEST_ROUND_DELAY"]
HTTP_TEST_INNER_RETRY_ENABLED = cfg["HTTP_TEST_INNER_RETRY_ENABLED"]
HTTP_TEST_MAX_RETRIES = cfg["HTTP_TEST_MAX_RETRIES"]
HTTP_TEST_RETRY_DELAY = cfg["HTTP_TEST_RETRY_DELAY"]
HTTP_TEST_METHOD = cfg["HTTP_TEST_METHOD"]
HTTP_LATENCY_WEIGHT = cfg["HTTP_LATENCY_WEIGHT"]
JITTER_WEIGHT = cfg["JITTER_WEIGHT"]
HTTP_JITTER_SAMPLES = cfg["HTTP_JITTER_SAMPLES"]
FILTER_IPV6_AVAILABILITY = cfg["FILTER_IPV6_AVAILABILITY"]
FILTER_BLOCKED_COUNTRIES_ENABLED = cfg["FILTER_BLOCKED_COUNTRIES_ENABLED"]
BLOCKED_COUNTRIES = cfg["BLOCKED_COUNTRIES"]
DNS_IP_RISK_FILTER_ENABLED = cfg["DNS_IP_RISK_FILTER_ENABLED"]
DNS_IP_RISK_MAX_LEVEL = cfg["DNS_IP_RISK_MAX_LEVEL"]
DNS_UPDATE_TARGET_COUNT = cfg["DNS_UPDATE_TARGET_COUNT"]
BANDWIDTH_SIZE_MB = cfg["BANDWIDTH_SIZE_MB"]
BANDWIDTH_TIMEOUT = cfg["BANDWIDTH_TIMEOUT"]
BANDWIDTH_RETRY_MAX = cfg["BANDWIDTH_RETRY_MAX"]
BANDWIDTH_RETRY_DELAY = cfg["BANDWIDTH_RETRY_DELAY"]
BANDWIDTH_URL_TEMPLATE = cfg["BANDWIDTH_URL_TEMPLATE"]
TLS_HANDSHAKE_MAX_S = cfg["TLS_HANDSHAKE_MAX_S"]
HANDSHAKE_MS = {}   # node_str -> TLS 握手毫秒，供最终列表展示
BANDWIDTH_PROCESS_BUFFER = cfg["BANDWIDTH_PROCESS_BUFFER"]
BANDWIDTH_CONNECT_TIMEOUT = cfg["BANDWIDTH_CONNECT_TIMEOUT"]
SPEED_WEIGHT = cfg["SPEED_WEIGHT"]
SCORE_SPEED_WEIGHT = cfg["SCORE_SPEED_WEIGHT"]
SCORE_LATENCY_WEIGHT = cfg["SCORE_LATENCY_WEIGHT"]
MAX_TCP_LATENCY_MS = cfg["MAX_TCP_LATENCY_MS"]
REGION_RESERVE_N = cfg["REGION_RESERVE_N"]

# 良心云保底名额（2026-09-25 用户拍板）：主池之外额外保留给 LX-良心云 源，
# 审查力度放宽 30%（TCP 260ms / TLS 2.6s / 带宽 ≥0.7MB）。候选来自
# fetch_sources 产出的 zip_nrt_lx.txt（过滤后全量 LX 候选，不占 120 配额），
# 与主池去重后按速度取前 slots 个，强制 #LX 标签；disabled 或文件缺失即整体跳过。
LX_RESERVE = cfg.get("LX_RESERVE") or {}
LX_RESERVE_ENABLED = bool(LX_RESERVE.get("enabled", False))
LX_RESERVE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), LX_RESERVE.get("file", "zip_nrt_lx.txt"))
LX_RESERVE_SLOTS = int(LX_RESERVE.get("slots", 10))
LX_RESERVE_MAX_LATENCY_MS = float(LX_RESERVE.get("max_latency_ms", 260))
LX_RESERVE_MAX_TLS_S = float(LX_RESERVE.get("max_tls_s", 2.6))
LX_RESERVE_MIN_BYTES = int(LX_RESERVE.get("min_bytes", 734003))

# =========================== 池历史（抗客观衰减） ===========================
# 依据：社区共识（BiuPing/月半菌/v2cross：CF anycast 路由与运营商 QoS 每天在变，
# "优选 IP 客观寿命 1-3 天"）+ 本机实测（2026-09-17 晚产的 30 个池，24h 内死 5 个，
# 且死者集中在当轮"最快"段 1/2/4/8/9 名 —— 说明单轮 min 抽样会把一次幸运当成绩）。
# 于是记录每轮入池 IP，下一轮给"近 N 轮反复进池"的 IP 一点加分，并打印存活率当作长期证据。
POOL_HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pool_history.json")


def _load_pool_history():
    """→ [{'ts':..., 'ips':[...]}, ...] 旧→新；文件缺失/损坏返回 []（首轮无加分，优雅降级）"""
    try:
        with open(POOL_HISTORY_FILE, encoding="utf-8") as fh:
            return (json.load(fh).get("rounds") or [])[-12:]
    except Exception:
        return []


def _save_pool_history(final_nodes, keep=8):
    """原子追加本轮入池 IP 与节点（ip:port），仅保留最近 keep 轮。
    nodes 用 ip:port 做身份，供下轮"在岗优先"精确匹配（地区标签可能变，端口不会）。"""
    rounds = _load_pool_history()
    ips = sorted({n.split(":")[0] for n in final_nodes})
    nodes = sorted({n.split("#")[0] for n in final_nodes})
    rounds.append({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "ips": ips, "nodes": nodes})
    tmp = POOL_HISTORY_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as fh:
        json.dump({"rounds": rounds[-keep:]}, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, POOL_HISTORY_FILE)


def incumbent_keys(rounds, window=1):
    """近 window 轮入池过的节点身份集合（'ip:port'）"""
    keys = set()
    for r in rounds[-window:] if window else []:
        for n in (r.get("nodes") or []):
            keys.add(n)
        for ip in (r.get("ips") or []):        # 兼容早期只存裸 IP 的历史
            keys.add(ip)
    return keys


def merge_incumbents(ranked_nodes, inc_keys, top_n, ratio):
    """在岗优先：上轮入池且本轮仍通过全部闸门的节点优先保留，其余名额按分数补位。
    依据：社区 stable 模式（lee1080/cf_auto_bestip：保留在岗 IP、只淘汰失效的再补位）
    + 本机实测（2026-09-18：两轮池零重叠，但老池 30 个里只有 6 个真死 → 换血大半是
    我们自己的相对排名造成的，不是 IP 不行）。ratio=0 时退化为纯排名。"""
    if not inc_keys or ratio <= 0 or top_n <= 0:
        return list(ranked_nodes[:top_n])
    keep_n = int(round(top_n * ratio))
    inc = [n for n in ranked_nodes if n.split("#")[0] in inc_keys][:keep_n]
    rest = [n for n in ranked_nodes if n not in set(inc)]
    return (inc + rest)[:top_n]


def load_cf_nets():
    """CF 官方 15 段（复用 fetch_sources 缓存的 cf_ranges.txt）"""
    import ipaddress as _ipa
    try:
        return [_ipa.ip_network(l.strip()) for l in open("cf_ranges.txt", encoding="utf-8") if l.strip()]
    except Exception:
        return None


def is_cf_official(ip, nets):
    import ipaddress as _ipa
    try:
        a = _ipa.ip_address(ip)
        return any(a in x for x in nets)
    except Exception:
        return False


def _exit_country(exit_details, node):
    """从可用性检测已拿到的 exit 信息里取落地国家（零额外请求）"""
    info = exit_details.get(node) or exit_details.get(node.split("#")[0]) or {}
    cc = str(info.get("country") or info.get("cc") or "").strip().upper()
    return cc if len(cc) == 2 else ""


def relabel_by_exit(selected, ranked_nodes, exit_details, allowed):
    """纠正落地标签，按 IP:port 去重；保留已实测通过的节点。

    白名单只用于候选粗筛（沿用 9/18 决定），标签相同不代表重复节点。
    """
    out, used, changed = [], set(), []

    def add(node, filling=False):
        base = node.split("#")[0]
        if base in used:
            return
        cc = _exit_country(exit_details, node)
        if filling and allowed and cc and cc not in allowed:
            return
        corrected = f"{base}#{cc}" if cc else node
        out.append(corrected)
        used.add(base)
        if corrected != node:
            changed.append(f"{base}→{cc}")

    for node in selected:
        add(node)
    want = len(selected)
    for node in ranked_nodes:
        if len(out) >= want:
            break
        add(node, filling=True)
    return out[:want], changed


def remap_node_metrics(selected, *maps):
    """标签变动后仍通过 IP:port 关联实测值，避免绕过链路闸门。"""
    for mapping in maps:
        by_endpoint = {node.split("#")[0]: value for node, value in mapping.items()}
        for node in selected:
            base = node.split("#")[0]
            if base in by_endpoint:
                mapping[node] = by_endpoint[base]


def pick_balanced(scored_nodes, top_n, ratio, nets):
    """最终池按"CF 官方段 / 他人反代"按比例选（ratio<=0 时退化为纯分数前 N）：
    各类内部按分数取，一方凑不满就用另一方补（宁可少配比也不缩池子）。
    返回 (节点列表, 实际官方数)。入参不要求预排序——函数内部自排，排序只此一处。"""
    scored_nodes = sorted(scored_nodes, key=lambda x: x[1], reverse=True)
    if not nets or ratio <= 0:
        return [it[0] for it in scored_nodes[:top_n]], 0
    off = [it for it in scored_nodes if is_cf_official(it[0].split(":")[0], nets)]
    prox = [it for it in scored_nodes if not is_cf_official(it[0].split(":")[0], nets)]
    want_off = int(round(top_n * ratio))
    a, b = off[:want_off], prox[: top_n - len(off[:want_off])]
    if len(a) + len(b) < top_n:                       # 有一方不够 → 用剩下的补
        used = {x[0] for x in a + b}
        fill = [it for it in scored_nodes if it[0] not in used]
        (b if len(a) >= want_off else a).extend(fill[: top_n - len(a) - len(b)])
    merged = sorted(a + b, key=lambda x: x[1], reverse=True)
    return [it[0] for it in merged][:top_n], len(a)


def _probe_alive(nodes, probes=2, timeout=2.0, workers=24):
    """对给定 'ip:port'（或含 #RG）列表做真实建链复测，返回 (alive, dead)"""
    def one(item):
        s = item.split("#")[0]
        ip, _, port = s.partition(":")
        lat, ok = test_tcp_latency(ip, int(port or 443), timeout=timeout, probes=probes)
        return item, ok
    alive, dead = [], []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for item, ok in ex.map(one, nodes):
            (alive if ok else dead).append(item)
    return alive, dead


def apply_region_reserve(scored_nodes, top_n, reserve_n):
    """地区备胎保底：先给"非主流地区"各留 reserve_n 个（按分数取该地区最优），
    再用全局最高分补齐剩余名额。返回按分数降序排列的节点列表。
    scored_nodes = [(node, score, ...), ...]（不要求预排序，函数内部自排）
    node 的地区取 '#' 后缀（如 1.2.3.4:443#JP）。"""
    if not scored_nodes:
        return []
    scored_nodes = sorted(scored_nodes, key=lambda x: x[1], reverse=True)
    def region_of(node):
        return node.split("#")[-1].strip() if "#" in node else "?"
    by_region = {}
    for item in scored_nodes:
        by_region.setdefault(region_of(item[0]), []).append(item)
    if reserve_n <= 0 or len(by_region) <= 1:
        return [item[0] for item in scored_nodes[:top_n]]
    dominant = max(by_region, key=lambda r: len(by_region[r]))
    picked, seen = [], set()
    for region, items in sorted(by_region.items(), key=lambda kv: -len(kv[1])):
        if region == dominant:
            continue
        for item in items[:reserve_n]:
            picked.append(item)
            seen.add(item[0])
    for item in scored_nodes:
        if len(picked) >= top_n:
            break
        if item[0] not in seen:
            picked.append(item)
            seen.add(item[0])
    picked.sort(key=lambda x: x[1], reverse=True)
    return [item[0] for item in picked[:top_n]]
IP_CALIBRATION_CONCURRENCY = cfg["IP_CALIBRATION_CONCURRENCY"]
MAX_WORKERS = cfg["MAX_WORKERS"]
AVAILABILITY_WORKERS = cfg["AVAILABILITY_WORKERS"]
FALLBACK_WORKERS = cfg["FALLBACK_WORKERS"]
BANDWIDTH_WORKERS = cfg["BANDWIDTH_WORKERS"]
HTTP_TEST_WORKERS = cfg["HTTP_TEST_WORKERS"]
DNS_UPDATE_MAX_RETRIES = cfg["DNS_UPDATE_MAX_RETRIES"]
DNS_UPDATE_RETRY_DELAY = cfg["DNS_UPDATE_RETRY_DELAY"]
GITHUB_SYNC_MAX_RETRIES = cfg["GITHUB_SYNC_MAX_RETRIES"]
GITHUB_SYNC_RETRY_DELAY = cfg["GITHUB_SYNC_RETRY_DELAY"]
GIT_SYNC_PROCESS_TIMEOUT = cfg["GIT_SYNC_PROCESS_TIMEOUT"]
AD_HEADER_ENABLED = cfg["AD_HEADER_ENABLED"]
AD_HEADER_LINES = cfg["AD_HEADER_LINES"]
AD_FOOTER_ENABLED = cfg["AD_FOOTER_ENABLED"]
AD_FOOTER_LINES = cfg["AD_FOOTER_LINES"]
AD_PERLINE_ENABLED = cfg["AD_PERLINE_ENABLED"]
AD_PERLINE_TEXT = cfg["AD_PERLINE_TEXT"]
IP_TXT_SHOW_BANDWIDTH = cfg["IP_TXT_SHOW_BANDWIDTH"]
IP_TXT_SHOW_HTTP_LATENCY = cfg["IP_TXT_SHOW_HTTP_LATENCY"]
IP_TXT_SHOW_HTTP_JITTER = cfg["IP_TXT_SHOW_HTTP_JITTER"]
IP_TXT_SHOW_LATENCY = cfg["IP_TXT_SHOW_LATENCY"]

if FORCE_DIRECT:
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        os.environ.pop(key, None)
    os.environ["NO_PROXY"] = "*"

socket.setdefaulttimeout(SOCKET_DEFAULT_TIMEOUT)

# ====================================================

def send_wxpusher_notification(content, summary):
    if not ENABLE_WXPUSHER:
        return
    try:
        payload = {
            "appToken": WXPUSHER_APP_TOKEN,
            "content": content,
            "summary": summary,
            "uids": WXPUSHER_UIDS
        }
        headers = {"Content-Type": "application/json; charset=utf-8"}
        resp = requests.post(
            WXPUSHER_API_URL,
            data=json.dumps(payload),
            headers=headers,
            timeout=(NOTIFY_CONNECT_TIMEOUT, NOTIFY_TIMEOUT)
        )
        if resp.status_code == 200:
            print("微信通知已发送")
        else:
            print(f"微信通知发送失败: {resp.status_code}")
    except Exception as e:
        print(f"微信通知异常: {e}")

# ==================== IP 风险等级查询 ====================
RISK_LEVEL_ORDER = {
    "极度纯净": 0,
    "纯净": 1,
    "轻微风险": 2,
    "高风险": 3,
    "极度危险": 4,
}

def get_ip_risk_level(ip):
    """查询单个 IP 的风险等级字符串，失败返回 '未知'"""
    url = f"https://api.ipapi.is/?q={ip}"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return "未知"

    company_score = data.get("company", {}).get("abuser_score")
    asn_score = data.get("asn", {}).get("abuser_score")
    security_flags = {
        "is_crawler": data.get("is_crawler", False),
        "is_proxy": data.get("is_proxy", False),
        "is_vpn": data.get("is_vpn", False),
        "is_tor": data.get("is_tor", False),
        "is_abuser": data.get("is_abuser", False),
        "is_bogon": data.get("is_bogon", False),
    }

    def extract_score(score_str):
        if not score_str:
            return 0.0
        match = re.match(r"([\d.]+)\s*\(([^)]+)\)", str(score_str).strip())
        if match:
            return float(match.group(1))
        try:
            return float(score_str)
        except (ValueError, TypeError):
            return 0.0

    company = extract_score(company_score)
    asn = extract_score(asn_score)
    base_score = ((company + asn) / 2) * 5

    risk_count = sum(1 for key in ["is_crawler", "is_proxy", "is_vpn", "is_tor", "is_abuser"]
                     if security_flags.get(key, False))
    final_score = base_score + risk_count * 0.15
    if security_flags.get("is_bogon", False):
        final_score += 1.0

    percentage = final_score * 100
    if percentage >= 100:
        return "极度危险"
    elif percentage >= 20:
        return "高风险"
    elif percentage >= 5:
        return "轻微风险"
    elif percentage >= 0.25:
        return "纯净"
    else:
        return "极度纯净"

# ==================== 自适应多数据源解析引擎 ====================
def extract_country_code(label):
    """从任意标签中提取标准两位国家代码（支持两位代码、三位代码映射、中文名、emoji国旗、混合无关文字）"""
    label = label.strip()
    if not label:
        return None

    tokens = re.split(r'[\s,;|/]+', label)

    # 1. 检查两位/三位代码
    for token in tokens:
        token_cleaned = re.sub(r'^[\d\s\-_.|#]+', '', token.strip())
        m3 = re.match(r'^([A-Z]{3})(?![A-Za-z])', token_cleaned)
        if m3 and m3.group(1) in ALPHA3_TO_ALPHA2:
            return ALPHA3_TO_ALPHA2[m3.group(1)]
        m2 = re.match(r'^([A-Z]{2})(?![A-Za-z])', token_cleaned)
        if m2 and m2.group(1) in CODE_SET:
            return m2.group(1)

    # 2. 中文子串提取（改进）
    for token in tokens:
        token_cleaned = re.sub(r'^[\d\s\-_.|#]+', '', token)
        cn_matches = re.findall(r'[\u4e00-\u9fff（）()]+', token_cleaned)
        for cn in cn_matches:
            code = CN_TO_CODE.get(cn)
            if code:
                return code

    # 3. 国旗 emoji
    emoji_chars = [c for c in label if '\U0001F1E6' <= c <= '\U0001F1FF']
    if len(emoji_chars) >= 2 and len(emoji_chars) % 2 == 0:
        first = ord(emoji_chars[0]) - 0x1F1E6
        second = ord(emoji_chars[1]) - 0x1F1E6
        if 0 <= first <= 25 and 0 <= second <= 25:
            return chr(first + ord('A')) + chr(second + ord('A'))

    return None


def _parse_json_nodes(data):
    nodes = []
    if isinstance(data, list):
        for item in data:
            nodes.extend(_parse_json_nodes(item))
    elif isinstance(data, dict):
        for key in ('nodes', 'data', 'result', 'list'):
            if key in data and isinstance(data[key], list):
                nodes.extend(_parse_json_nodes(data[key]))
                break
        ip = data.get('ip') or data.get('host')
        port = data.get('port')
        code = data.get('country') or data.get('cc')
        if ip and port and code:
            nodes.append(f"{ip}:{port}#{code.upper()}")
    elif isinstance(data, str):
        nodes.extend(_parse_text_nodes(data))
    return nodes


def _query_country(ip, port):
    try:
        resp = requests.get(
            AVAILABILITY_CHECK_API,
            params={"proxyip": f"{ip}:{port}"},
            timeout=(AVAILABILITY_CONNECT_TIMEOUT, AVAILABILITY_TIMEOUT)
        )
        if resp.status_code == 200:
            data = resp.json()
            country = data.get("probe_results", {}).get("ipv4", {}).get("exit", {}).get("country", "")
            if country and len(country) == 2:
                return country.upper()
    except Exception:
        pass
    return None


def _resolve_countries_batch(ipports):
    results = {}
    total = len(ipports)
    completed = 0
    last_print = time.time()

    def worker(ipport):
        ip, port = ipport.rsplit(':', 1)
        return ipport, _query_country(ip, port)

    with ThreadPoolExecutor(max_workers=FALLBACK_WORKERS) as executor:
        futures = {executor.submit(worker, ipp): ipp for ipp in ipports}
        for future in as_completed(futures):
            try:
                ipport, code = future.result()
                results[ipport] = code
            except Exception:
                results[futures[future]] = None
            completed += 1
            now = time.time()
            if now - last_print >= PROGRESS_PRINT_INTERVAL or completed == total:
                print(f"\r[备用API查询] 进度：{completed}/{total} ({(completed/total)*100:.1f}%)", end="", flush=True)
                last_print = now

    if total > 0:
        print()
    return results


def _parse_text_nodes(text):
    nodes = []
    pending = []

    tokens = text.split()
    for token in tokens:
        pure_match = re.match(r'^(\d+\.\d+\.\d+\.\d+:\d+)$', token)
        if pure_match:
            pending.append(pure_match.group(1))
            continue

        if '#' not in token:
            continue
        try:
            ipport, label = token.split('#', 1)
        except ValueError:
            continue
        ipport = ipport.strip()
        label = label.strip()

        if ipport.startswith('['):
            continue
        if not re.match(r'^\d+\.\d+\.\d+\.\d+:\d+$', ipport):
            continue

        code = extract_country_code(label)
        if code:
            nodes.append(f"{ipport}#{code}")
        else:
            pending.append(ipport)

    if pending:
        print(f"{len(pending)} 个节点未能识别或缺少国家，通过可用性检测 API 查询国家...")
        resolved = _resolve_countries_batch(pending)
        for ipport, code in resolved.items():
            if code:
                nodes.append(f"{ipport}#{code}")

    return nodes


def parse_adaptive(text):
    text = text.strip()
    if not text:
        return []

    if text.startswith('{') or text.startswith('['):
        try:
            data = json.loads(text)
            return _parse_json_nodes(data)
        except (json.JSONDecodeError, Exception):
            pass

    return _parse_text_nodes(text)


def fetch_additional_source(url):
    if not url:
        return []

    # 本地文件源（file:/// 路径），由前置脚本（如 fetch_zip_nrt.py）产出
    if url.startswith("file://"):
        local = url[len("file://"):]
        try:
            with open(local, "r", encoding="utf-8") as f:
                nodes = parse_adaptive(f.read())
            print(f"从本地源 {local} 解析出 {len(nodes)} 个节点。")
            return nodes
        except Exception as e:
            print(f"读取本地源失败 ({local}): {e}")
            return []

    for attempt in range(1, FETCH_MAX_RETRIES + 1):
        try:
            print(f"正在请求数据源 {url} (尝试 {attempt}/{FETCH_MAX_RETRIES}) ...")
            headers = {"Accept-Encoding": "gzip, deflate, br, zstd"}
            resp = requests.get(url, timeout=(FETCH_CONNECT_TIMEOUT, FETCH_TIMEOUT), headers=headers)
            resp.raise_for_status()
            nodes = parse_adaptive(resp.text)
            print(f"从 {url} 解析出 {len(nodes)} 个节点。")
            return nodes
        except Exception as e:
            print(f"请求或解析失败 ({url}): {e}")
            if attempt < FETCH_MAX_RETRIES:
                print(f"等待 {FETCH_RETRY_DELAY} 秒后重试...")
                time.sleep(FETCH_RETRY_DELAY)
            else:
                print(f"已尝试 {FETCH_MAX_RETRIES} 次，放弃该数据源。")
                return []

# =========================== IP 地区校准模块 ===========================
class IpInfoAsync:
    def __init__(self, token_list, concurrency, min_interval, trust_env, failure_threshold):
        self.token_list = token_list
        self.current_token_index = 0
        self.token_lock = asyncio.Lock()
        self.semaphore = asyncio.Semaphore(concurrency)
        self.min_interval = min_interval
        self.last_request_time = 0
        self.rate_lock = asyncio.Lock()
        self.session = None
        self.trust_env = trust_env
        self.failure_threshold = failure_threshold
        self.token_failures = [0] * len(token_list)

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(trust_env=self.trust_env)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    @property
    def current_token(self):
        if self.current_token_index < len(self.token_list):
            return self.token_list[self.current_token_index]
        return None

    async def switch_token(self, silent=False):
        async with self.token_lock:
            if self.current_token_index + 1 < len(self.token_list):
                self.current_token_index += 1
                return True
            else:
                return False

    async def _rate_limit(self):
        async with self.rate_lock:
            now = asyncio.get_event_loop().time()
            wait = self.last_request_time + self.min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self.last_request_time = asyncio.get_event_loop().time()

    async def get_ip_details(self, ip_address):
        attempted = 0
        max_attempts = len(self.token_list)
        while attempted < max_attempts:
            token = self.current_token
            if token is None:
                return None
            idx = self.current_token_index
            if self.token_failures[idx] >= self.failure_threshold:
                if await self.switch_token():
                    attempted += 1
                    continue
                else:
                    return None

            url = f"https://ipinfo.io/{ip_address}/json?token={token}" if ip_address else f"https://ipinfo.io/json?token={token}"
            await self._rate_limit()
            async with self.semaphore:
                try:
                    async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 429:
                            self.token_failures[idx] += 1
                            if await self.switch_token():
                                attempted += 1
                                continue
                            else:
                                return None
                        resp.raise_for_status()
                        data = await resp.json()
                        self.token_failures[idx] = 0
                        country = data.get("country", "Unknown")
                        if country == "Unknown":
                            if await self.switch_token():
                                attempted += 1
                                continue
                            else:
                                return None
                        return {
                            "CountryCode": country,
                            "Region": data.get("region", "Unknown"),
                            "City": data.get("city", "Unknown"),
                            "ASN": data.get("org", "").split(" ")[0] if data.get("org", "").startswith("AS") else "Unknown",
                            "ISP": data.get("org", "").split(" ", 1)[-1] if " " in data.get("org", "") else data.get("org", "Unknown"),
                        }
                except (asyncio.TimeoutError, aiohttp.ClientError):
                    self.token_failures[idx] += 1
                    if await self.switch_token():
                        attempted += 1
                        continue
                    else:
                        return None
        return None

def load_tokens(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def load_ipinfo_cache(cache_file):
    if not os.path.exists(cache_file):
        return {}
    cache = {}
    with open(cache_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or '#' not in line:
                continue
            ipport, tag = line.split('#', 1)
            cache[ipport.strip()] = tag.strip()
    return cache

def save_ipinfo_cache(cache_file, new_records):
    with open(cache_file, "a", encoding="utf-8") as f:
        for ipport, tag in new_records:
            f.write(f"{ipport}#{tag}\n")

def sort_cache_file(cache_file):
    if not os.path.exists(cache_file):
        return
    with open(cache_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    parsed = []
    for line in lines:
        line = line.strip()
        if not line or '#' not in line:
            continue
        ipport, tag = line.split('#', 1)
        ip_str = ipport.split(':')[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        parsed.append((ip_obj, line))

    parsed.sort(key=lambda x: x[0])

    with open(cache_file, "w", encoding="utf-8") as f:
        for _, line in parsed:
            f.write(line + "\n")

async def validate_tokens(token_list, concurrency, min_interval, trust_env):
    valid = []
    async with IpInfoAsync(token_list, concurrency, min_interval, trust_env, TOKEN_FAILURE_THRESHOLD) as handler:
        tasks = [asyncio.ensure_future(handler.get_ip_details("")) for _ in token_list]
        total = len(tasks)
        completed = 0
        for coro in asyncio.as_completed(tasks):
            await coro
            completed += 1
            print(f"\rToken 校验进度：{completed}/{total}", end="", flush=True)
        print()
        for i, task in enumerate(tasks):
            try:
                res = task.result()
                if res and res.get("CountryCode") != "Unknown":
                    valid.append(token_list[i])
            except:
                pass
    return valid

async def query_new_ips(new_ips, token_list, concurrency, min_interval, trust_env,
                        ipport_map=None, cache_file=None):
    result = {}
    if not new_ips or not token_list:
        return result

    print(f"需要查询 {len(new_ips)} 个新 IP...")
    async with IpInfoAsync(token_list, concurrency, min_interval, trust_env, TOKEN_FAILURE_THRESHOLD) as handler:
        tasks = []
        for ip in new_ips:
            task = asyncio.ensure_future(handler.get_ip_details(ip))
            task.my_ip = ip
            tasks.append(task)
        total = len(tasks)
        completed = 0
        failed = 0

        f = None
        if cache_file:
            f = open(cache_file, "a", encoding="utf-8")

        try:
            pending = set(tasks)
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    ip = task.my_ip
                    try:
                        info = task.result()
                    except Exception:
                        info = None
                    completed += 1
                    if info and info.get("CountryCode") != "Unknown":
                        tag_parts = [info["CountryCode"]]
                        if info.get("Region") and info["Region"] != "Unknown":
                            tag_parts.append(info["Region"])
                        if info.get("City") and info["City"] != "Unknown":
                            tag_parts.append(info["City"])
                        if info.get("ASN") and info["ASN"] != "Unknown":
                            tag_parts.append(info["ASN"])
                        if info.get("ISP") and info["ISP"] != "Unknown":
                            tag_parts.append(info["ISP"])
                        tag = " ".join(tag_parts)
                        result[ip] = tag
                        if f and ipport_map and ip in ipport_map:
                            for ipport in ipport_map[ip]:
                                f.write(f"{ipport}#{tag}\n")
                                f.flush()
                    else:
                        failed += 1
                    print(f"\r[{completed}/{total}] 地区校准...", end="", flush=True)
        finally:
            if f:
                f.close()
    print()
    if total > 0 and failed == total:
        send_wxpusher_notification("IP地区校准：所有IP查询均失败，可能所有token均已失效。", "IP校准全失败")
        print("警告：所有 IP 地区校准失败，可能所有 token 已失效。")
    return result

def calibrate_regions(nodes, token_file, cache_file):
    if not IP_CALIBRATION_ENABLED:
        print("IP 地区校准已禁用，跳过。")
        return

    token_list = load_tokens(token_file)
    if not token_list:
        print("valid_tokens.txt 为空，IP 地区校准跳过。")
        return

    trust_env = not FORCE_DIRECT

    print("正在进行 token 有效性校验...")
    valid_tokens = asyncio.run(validate_tokens(token_list, IP_CALIBRATION_CONCURRENCY, IP_CALIBRATION_MIN_INTERVAL, trust_env))
    if not valid_tokens:
        print("所有 token 均已失效，地区校准跳过。")
        send_wxpusher_notification("IP地区校准：所有token均已失效，本次校准跳过。", "IP校准 Token 耗尽")
        return
    print(f"有效 token 数量: {len(valid_tokens)}")

    ipport_set = set()
    for node in nodes:
        ipport = node.split('#')[0]
        ipport_set.add(ipport)

    cache = load_ipinfo_cache(cache_file)
    cached_ipports = set(cache.keys())
    new_ipports = ipport_set - cached_ipports

    if not new_ipports:
        print("所有 IP 已在缓存中，无需查询。")
    else:
        new_ips_set = set()
        ip_to_ipports = defaultdict(list)
        for ipport in new_ipports:
            ip = ipport.split(':')[0]
            new_ips_set.add(ip)
            ip_to_ipports[ip].append(ipport)

        print(f"检测到 {len(new_ipports)} 个新 IP:端口，涉及 {len(new_ips_set)} 个唯一 IP，开始查询...")
        ip_info = asyncio.run(query_new_ips(
            list(new_ips_set),
            valid_tokens,
            IP_CALIBRATION_CONCURRENCY,
            IP_CALIBRATION_MIN_INTERVAL,
            trust_env,
            ipport_map=ip_to_ipports,
            cache_file=cache_file
        ))

        for ip, tag in ip_info.items():
            for ipport in ip_to_ipports.get(ip, []):
                cache[ipport] = tag

    for i, node in enumerate(nodes):
        ipport = node.split('#')[0]
        tag = cache.get(ipport)
        if tag:
            country_code = tag.split()[0]
            nodes[i] = f"{ipport}#{country_code}"

    sort_cache_file(cache_file)

# =========================== 核心测试、筛选、测速及更新函数 ===========================

def test_tcp_latency(ip, port, timeout=TIMEOUT, probes=TCP_PROBES):
    """TCP 建链探测，probes 次后按 TCP_AGGREGATION 聚合（median 默认）。
    2026-09-18：单轮 min 会选到"一次幸运抽样"的 IP → 一晚产的池 24h 死 5/30 且死者集中在当轮最快段。
    median-of-N 抗 flash-in-the-pan（瞬间快但下一分钟就挂），若需旧口径可 set TCP_AGGREGATION="min"。”"""
    lats = []
    for _ in range(probes):
        try:
            start = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, int(port)))
            lats.append(time.time() - start)
        except Exception:
            continue
    if not lats:
        return float("inf"), 0
    lats.sort()
    # Aggregate mode
    agg = TCP_AGGREGATION.lower().strip()
    if agg == "min":
        return lats[0], len(lats)
    return lats[len(lats) // 2], len(lats)

def test_node(node_str):
    m = NODE_PATTERN.match(node_str)
    if not m:
        return None
    ip, port, country = m.groups()
    min_lat, success = test_tcp_latency(ip, port)
    if success == 0 or (success / TCP_PROBES) < MIN_SUCCESS_RATE:
        return None
    return (node_str, min_lat, country, success)

def check_availability(node_str):
    m = IP_PORT_PATTERN.match(node_str)
    if not m:
        return (node_str, False, "unknown", {})
    ip, port = m.group(1), m.group(2)
    proxyip = f"{ip}:{port}"

    best_stack = "unknown"
    best_exit_info = {}
    success = False

    max_attempts = AVAILABILITY_INNER_RETRY_MAX + 1 if AVAILABILITY_INNER_RETRY_ENABLED else 1
    retry_delay = AVAILABILITY_INNER_RETRY_DELAY if AVAILABILITY_INNER_RETRY_ENABLED else 0

    for attempt in range(max_attempts):
        try:
            resp = requests.get(
                AVAILABILITY_CHECK_API,
                params={"proxyip": proxyip},
                timeout=(AVAILABILITY_CONNECT_TIMEOUT, AVAILABILITY_TIMEOUT)
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success") is True:
                    success = True
                    best_stack = data.get("inferred_stack", "unknown")
                    probe = data.get("probe_results", {}).get("ipv6") or data.get("probe_results", {}).get("ipv4") or {}
                    best_exit_info = probe.get("exit", {})
                    break
        except Exception:
            pass
        if attempt < max_attempts - 1 and retry_delay > 0:
            time.sleep(retry_delay)

    return (node_str, success, best_stack, best_exit_info)

def check_http_server(node_str, timeout, max_retries, retry_delay, method, connect_timeout, inner_retry_enabled):
    m = IP_PORT_PATTERN.match(node_str)
    if not m:
        return (node_str, False, "parse_error", 0.0, 0.0)
    ip, port = m.group(1), m.group(2)
    url = f"http://{ip}:{port}/cdn-cgi/trace"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    }

    test_rounds = max(3, HTTP_JITTER_SAMPLES)
    latencies = []
    for _ in range(test_rounds):
        try:
            start = time.time()
            request_kwargs = {
                "timeout": (connect_timeout, timeout),
                "verify": False,
                "allow_redirects": False,
                "headers": headers,
                "proxies": {"http": None, "https": None}
            }

            if method.upper() == "HEAD":
                resp = requests.head(url, **request_kwargs)
            else:
                resp = requests.get(url, **request_kwargs)

            lat = (time.time() - start) * 1000
            if resp.status_code != 400:
                return (node_str, False, f"status_{resp.status_code}", 0.0, 0.0)
            server = resp.headers.get("server", "")
            if not server.lower().startswith("cloudflare"):
                return (node_str, False, server, 0.0, 0.0)
            latencies.append(lat)
        except Exception:
            return (node_str, False, "connection_error", 0.0, 0.0)

    if len(latencies) < test_rounds:
        return (node_str, False, "not_enough_samples", 0.0, 0.0)

    avg_lat = sum(latencies) / len(latencies)
    variance = sum((l - avg_lat) ** 2 for l in latencies) / len(latencies)
    jitter = variance ** 0.5
    return (node_str, True, "cloudflare", avg_lat, jitter)

def availability_filter_candidates(candidates):
    if not TEST_AVAILABILITY or not candidates:
        return candidates, {}, {}

    print(f"\n对 {len(candidates)} 个候选节点进行可用性二次筛选...")
    passed = []
    ip_info = {}
    exit_details = {}
    completed = 0
    total = len(candidates)
    last_print = time.time()

    with ThreadPoolExecutor(max_workers=AVAILABILITY_WORKERS) as executor:
        futures = {executor.submit(check_availability, node): node for node in candidates}
        for future in as_completed(futures):
            completed += 1
            node_str, ok, stack, exit_info = future.result()
            if ok:
                passed.append(node_str)
                ip_info[node_str] = stack
                exit_details[node_str] = exit_info
            now = time.time()
            if now - last_print >= PROGRESS_PRINT_INTERVAL or completed == total:
                print(f"\r[可用性检测] 进度：{completed}/{total} ({(completed/total)*100:.1f}%) 通过数量：{len(passed)}", end="", flush=True)
                last_print = now
    print()
    return passed, ip_info, exit_details

def availability_filter_with_retry(candidates):
    if not TEST_AVAILABILITY or not candidates:
        return candidates, {}, {}

    passed = []
    ip_info = {}
    exit_details = {}
    for attempt in range(1, AVAILABILITY_RETRY_MAX + 1):
        print(f"\n[可用性检测] 第 {attempt} 轮检测...")
        passed, ip_info, exit_details = availability_filter_candidates(candidates)
        if passed:
            print(f"可用性检测通过 {len(passed)} 个节点")
            return passed, ip_info, exit_details
        if attempt < AVAILABILITY_RETRY_MAX:
            print(f"本轮可用性检测通过率为 0%，等待 {AVAILABILITY_RETRY_DELAY} 秒后重试...")
            time.sleep(AVAILABILITY_RETRY_DELAY)

    print(f"可用性检测经 {AVAILABILITY_RETRY_MAX} 轮重试后仍无节点通过。")
    send_wxpusher_notification(
        content=f"IP 可用性检测经 {AVAILABILITY_RETRY_MAX} 轮重试后仍无节点通过，已跳过过滤，使用原候选列表继续。",
        summary="可用性检测全部失败"
    )
    return candidates, {}, {}

def http_server_filter(candidates, config):
    if not config.get("HTTP_TEST_ENABLED", False) or not candidates:
        return candidates, {}, {}

    timeout = HTTP_TEST_TIMEOUT
    connect_timeout = HTTP_TEST_CONNECT_TIMEOUT
    max_retries = HTTP_TEST_MAX_RETRIES
    retry_delay = HTTP_TEST_RETRY_DELAY
    inner_retry_enabled = HTTP_TEST_INNER_RETRY_ENABLED
    workers = HTTP_TEST_WORKERS
    method = HTTP_TEST_METHOD
    max_rounds = HTTP_TEST_MAX_ROUNDS
    round_delay = HTTP_TEST_ROUND_DELAY

    for round_num in range(1, max_rounds + 1):
        print(f"\n[HTTP检测] 第 {round_num} 轮检测...")
        print(f"\n对 {len(candidates)} 个候选节点进行 HTTP 二次筛选...")

        passed = []
        http_latency_map = {}
        http_jitter_map = {}
        total = len(candidates)
        completed = 0
        last_print = time.time()

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {
                executor.submit(check_http_server, node, timeout, max_retries, retry_delay, method, connect_timeout, inner_retry_enabled): node
                for node in candidates
            }
            for future in as_completed(future_map):
                node_str, valid, server, http_lat, http_jitter = future.result()
                completed += 1
                if valid:
                    passed.append(node_str)
                    http_latency_map[node_str] = http_lat
                    http_jitter_map[node_str] = http_jitter
                now = time.time()
                if now - last_print >= PROGRESS_PRINT_INTERVAL or completed == total:
                    print(f"\r[HTTP检测] 进度：{completed}/{total} ({(completed/total)*100:.1f}%) 通过数量：{len(passed)}", end="", flush=True)
                    last_print = now

        print()
        if passed:
            print(f"HTTP检测通过 {len(passed)} 个节点")
            return passed, http_latency_map, http_jitter_map
        elif round_num < max_rounds:
            print(f"本轮 HTTP 检测通过率为 0%，等待 {round_delay} 秒后重试...")
            time.sleep(round_delay)

    send_wxpusher_notification(
        content=f"HTTP检测经 {max_rounds} 轮重试后仍无节点通过，已降级使用过滤前列表。",
        summary="HTTP检测全部失败"
    )
    print(f"HTTP检测经 {max_rounds} 轮重试后仍无节点通过，降级使用过滤前候选列表。")
    return candidates, {}, {}

def measure_bandwidth_curl(node_str, tls_max_s=None, min_bytes=None):
    """单节点带宽测速。默认参数=主池口径（整档下载 + TLS_HANDSHAKE_MAX_S 硬门槛）；
    传 tls_max_s / min_bytes 即为放宽口径（LX 保底专用），其余逻辑完全同源。"""
    m = IP_PORT_PATTERN.match(node_str)
    if not m:
        return (node_str, 0)
    ip, port = m.group(1), m.group(2)
    port_int = int(port)

    # ---------- 端口与协议的映射 ----------
    HTTP_PORTS = {80, 8080, 8880, 2052, 2082, 2086, 2095}
    HTTPS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}

    if port_int in HTTP_PORTS:
        scheme = "http"
        insecure_flag = []          # HTTP 不需要 --insecure
    elif port_int in HTTPS_PORTS:
        scheme = "https"
        insecure_flag = ["--insecure"]
    else:
        # 未知端口，默认尝试 https（保险）
        scheme = "https"
        insecure_flag = ["--insecure"]
    # ---------------------------------------

    null_device = "NUL" if sys.platform == "win32" else "/dev/null"
    expected_size = int(BANDWIDTH_SIZE_MB * 1024 * 1024)
    # 放宽口径：tls_cap 覆盖硬门槛；min_bytes 给出最低下载字节数（默认 None=主池的整档精确口径）
    tls_cap = TLS_HANDSHAKE_MAX_S if tls_max_s is None else tls_max_s

    # 用模板生成最终 URL，替换 {scheme}、{port}、{bytes}
    url = BANDWIDTH_URL_TEMPLATE.format(
        scheme=scheme,
        port=port,
        bytes=int(BANDWIDTH_SIZE_MB * 1024 * 1024)
    )
    target = urlsplit(url)
    if target.scheme not in ("https", "http") or not target.hostname:
        return (node_str, 0)
    target_port = target.port or (443 if target.scheme == "https" else 80)
    if target_port != port_int:
        return (node_str, 0)

    curl_cmd = [
        "curl", "-q", "-sS", "-o", null_device,
        "-w", "%{size_download} %{time_starttransfer} %{time_total} %{time_appconnect} %{time_connect} %{http_code} %{remote_ip}",
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "--http1.1",  # 本机 curl (mingw/system32) 不支持 --http2，会直接退出码2
        "--noproxy", "*",
        "--resolve", f"{target.hostname}:{port}:{ip}",
        "--connect-timeout", str(BANDWIDTH_CONNECT_TIMEOUT),
        "--max-time", str(BANDWIDTH_TIMEOUT),
    ] + insecure_flag + [url]   # 动态添加 --insecure（如果是 https）

    try:
        # 注意：必须使用 bytes 模式（不加 text=True/encoding），
        # 否则 subprocess 内部 reader 线程在 Windows 下按 utf-8 解码管道时，
        # 遇到 curl 输出中的非 UTF-8 字节（如 GBK 区域设置的本地化消息）会在
        # _readerthread 中抛出 UnicodeDecodeError，导致整个测速线程崩溃。
        result = subprocess.run(curl_cmd, capture_output=True,
                                timeout=BANDWIDTH_TIMEOUT + BANDWIDTH_PROCESS_BUFFER)
        stdout_str = (result.stdout or b"").decode("utf-8", errors="replace")
        stderr_str = (result.stderr or b"").decode("utf-8", errors="replace")
        if result.returncode == 0 and stdout_str.strip():
            parts = stdout_str.strip().split()
            if len(parts) == 7:
                if parts[5] != "200" or ipaddress.ip_address(parts[6]) != ipaddress.ip_address(ip):
                    return (node_str, 0)
                size_bytes = float(parts[0])
                if not math.isfinite(size_bytes):
                    return (node_str, 0)
                if min_bytes is None:
                    # 主池口径：必须整档下载（2026-09-25 Codex 严格化）
                    if size_bytes != expected_size:
                        return (node_str, 0)
                elif size_bytes < min_bytes:
                    # 放宽口径：达到最低字节数即可
                    return (node_str, 0)
                time_starttransfer = float(parts[1])
                time_total = float(parts[2])
                time_appconnect = float(parts[3])
                time_connect = float(parts[4])
                if not all(math.isfinite(t) and t >= 0 for t in
                           (time_starttransfer, time_total, time_appconnect, time_connect)):
                    return (node_str, 0)
                if time_appconnect > 0:
                    # appconnect 含 TCP；评分另外计 TCP，只添加 TLS 增量，避免重复计数。
                    HANDSHAKE_MS[node_str] = round(max(0.0, time_appconnect - time_connect) * 1000)
                    # 建链总耗时硬门槛（主池 2s；LX 保底口径放宽至 tls_max_s）
                    if tls_cap > 0 and time_appconnect > tls_cap:
                        return (node_str, 0)
                transfer_time = time_total - time_starttransfer
                if transfer_time > 0:
                    speed_mbps = (size_bytes * 8) / (transfer_time * 1000 * 1000)
                    return (node_str, speed_mbps)
        elif stderr_str.strip():
            # curl 失败时打印其错误信息（已安全解码），便于排查
            print(f"\n[带宽测速] {node_str} curl 退出码 {result.returncode}: {stderr_str.strip().splitlines()[0]}")
    except Exception:
        pass
    return (node_str, 0)

def bandwidth_filter(candidates):
    if not candidates:
        return []

    if not shutil.which("curl"):
        print("未检测到 curl 命令，带宽测速将跳过。")
        return []

    print(f"\n开始带宽测速（对前 {len(candidates)} 个节点，并发 {BANDWIDTH_WORKERS}，超时 {BANDWIDTH_TIMEOUT}s）...")
    results = []
    completed = 0
    total = len(candidates)
    last_print = time.time()

    with ThreadPoolExecutor(max_workers=BANDWIDTH_WORKERS) as executor:
        futures = {executor.submit(measure_bandwidth_curl, node): node for node in candidates}
        for future in as_completed(futures):
            completed += 1
            node, speed = future.result()
            if speed > 0:
                results.append((node, speed))
            now = time.time()
            if now - last_print >= PROGRESS_PRINT_INTERVAL or completed == total:
                print(f"\r[带宽测速] 进度：{completed}/{total} ({(completed/total)*100:.1f}%)", end="", flush=True)
                last_print = now

    print()
    results.sort(key=lambda x: x[1], reverse=True)
    return results

def batch_update_cloudflare_dns(ip_list, ip_info=None, full_bw_results=None, target_count=None, latency_map=None, http_latency_map=None, http_jitter_map=None):
    if not CF_ENABLED:
        print("Cloudflare DNS 批量更新未启用。")
        return

    if target_count is None:
        target_count = DNS_UPDATE_TARGET_COUNT

    dns_content_list = []
    dns_node_list = []
    filtered_by_port = 0
    filtered_by_ipv6 = 0
    filtered_by_country = 0
    filtered_by_risk = 0
    risk_fallback_ip_list = []
    risk_fallback_node_list = []

    record_type = DNS_RECORD_TYPE.upper()
    if record_type not in ("A", "TXT"):
        print(f"不支持的 DNS_RECORD_TYPE: {record_type}，已跳过 DNS 更新。")
        return

    risk_map = {}
    if DNS_IP_RISK_FILTER_ENABLED and full_bw_results:
        ip_set = set()
        for node_str, _ in full_bw_results:
            if ':' in node_str:
                ip_set.add(node_str.split(':')[0])
        if ip_set:
            workers = min(FALLBACK_WORKERS, len(ip_set))
            print(f"正在并发查询 {len(ip_set)} 个 IP 的风险等级（并发 {workers}）...")
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futures = {ex.submit(get_ip_risk_level, ip): ip for ip in ip_set}
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        risk_map[ip] = future.result()
                    except Exception:
                        risk_map[ip] = "未知"
            print("风险等级查询完成。")

    if full_bw_results and ip_info:
        blocked_set = set()
        if FILTER_BLOCKED_COUNTRIES_ENABLED:
            blocked_set = {c.upper() for c in BLOCKED_COUNTRIES}

        for node_str, speed in full_bw_results:
            if ':' not in node_str:
                continue
            parts = node_str.split(':')
            if len(parts) < 2:
                continue
            pure_ip = parts[0]
            port = parts[1].split('#')[0]

            if record_type == "A" and port != '443':
                filtered_by_port += 1
                continue

            if FILTER_IPV6_AVAILABILITY:
                stack = ip_info.get(node_str, "unknown")
                if stack == "ipv6_only":
                    filtered_by_ipv6 += 1
                    continue

            if blocked_set and '#' in node_str:
                country = node_str.split('#')[-1].split()[0].upper()
                if country in blocked_set:
                    filtered_by_country += 1
                    continue

            if DNS_IP_RISK_FILTER_ENABLED:
                risk_fallback_ip_list.append(pure_ip)
                risk_fallback_node_list.append(node_str)

            if DNS_IP_RISK_FILTER_ENABLED:
                risk_level = risk_map.get(pure_ip, "未知")
                max_level = DNS_IP_RISK_MAX_LEVEL
                if risk_level == "未知" or RISK_LEVEL_ORDER.get(risk_level, 99) > RISK_LEVEL_ORDER.get(max_level, 2):
                    filtered_by_risk += 1
                    continue

            if record_type == "A":
                dns_content_list.append(pure_ip)
            else:
                dns_content_list.append(f"{pure_ip}:{port}")
            dns_node_list.append(node_str)

            if len(dns_content_list) >= target_count:
                break

        if DNS_IP_RISK_FILTER_ENABLED and not dns_content_list and filtered_by_risk > 0:
            send_wxpusher_notification(
                content="风险等级检测全部失败：所有候选节点均因风险等级过高或 API 查询失败被过滤，已回退到无风险等级过滤的候选列表。",
                summary="风险等级检测全部失败"
            )
            fallback_content = []
            fallback_nodes = []
            for i, (ip, node) in enumerate(zip(risk_fallback_ip_list, risk_fallback_node_list)):
                if record_type == "A":
                    fallback_content.append(ip)
                else:
                    ip_port = node.split('#')[0]
                    fallback_content.append(ip_port)
                fallback_nodes.append(node)
                if len(fallback_content) >= target_count:
                    break
            dns_content_list = fallback_content
            dns_node_list = fallback_nodes

        filter_parts = []
        if filtered_by_port > 0:
            filter_parts.append(f"非443端口过滤({filtered_by_port}个)")
        if FILTER_IPV6_AVAILABILITY:
            filter_parts.append(f"IPv6落地过滤({filtered_by_ipv6}个)")
        if FILTER_BLOCKED_COUNTRIES_ENABLED:
            filter_parts.append(f"DNS黑名单过滤({filtered_by_country}个)")
        if DNS_IP_RISK_FILTER_ENABLED and filtered_by_risk > 0:
            filter_parts.append(f"风险等级过滤({filtered_by_risk}个)")
        filter_str = " + ".join(filter_parts) if filter_parts else "无过滤"
        print(f"从 {len(full_bw_results)} 个测速节点中筛选出 {len(dns_content_list)} 个{'IP' if record_type=='A' else 'IP:端口'} 用于 DNS 更新（{filter_str}）。")

    if not dns_content_list:
        if ip_list:
            print("未能从完整测速结果构建 DNS 列表，降级使用 ip.txt 中的 IP。")
            if record_type == "A":
                dns_content_list = ip_list
                dns_node_list = ip_list
            else:
                print("TXT 模式需要端口信息，但降级数据中无端口，DNS 更新跳过。")
                return
        else:
            msg = "没有可用的 IP 用于 DNS 更新，跳过。"
            print(msg)
            send_wxpusher_notification(content=msg, summary="DNS 更新跳过")
            return

    seen = set()
    unique_content = []
    unique_nodes = []
    for content, node in zip(dns_content_list, dns_node_list):
        if content not in seen:
            seen.add(content)
            unique_content.append(content)
            unique_nodes.append(node)
    dns_content_list = unique_content
    dns_node_list = unique_nodes

    print(f"\n准备将以下 {len(dns_content_list)} 个{'IP' if record_type=='A' else 'IP:端口'} 更新到 Cloudflare DNS（记录类型 {record_type}）:")
    speed_map = {}
    if full_bw_results:
        speed_map = {node: speed for node, speed in full_bw_results}
    for i, (content, node) in enumerate(zip(dns_content_list, dns_node_list), 1):
        speed = speed_map.get(node, 0)
        lat_ms = float('inf')
        http_lat_ms = None
        http_jitter_ms = None
        if latency_map and node in latency_map:
            lat_ms = latency_map[node] * 1000
        if http_latency_map and node in http_latency_map:
            http_lat_ms = http_latency_map[node]
        if http_jitter_map and node in http_jitter_map:
            http_jitter_ms = http_jitter_map[node]

        # 让显示标签带上国家代码
        display_label = node if '#' in node else content
        line = f"{i}. {display_label} 速度 {speed:.2f} Mbps"
        if http_lat_ms is not None:
            line += f" 延迟 {http_lat_ms:.2f} ms"
        if http_jitter_ms is not None:
            line += f" 抖动 {http_jitter_ms:.2f} ms"
        if lat_ms != float('inf'):
            line += f" 延迟 {lat_ms:.2f} ms"
        print(line)

    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }

    if record_type == "A":
        for attempt in range(1, DNS_UPDATE_MAX_RETRIES + 1):
            print(f"\n[DNS 更新] 尝试 {attempt}/{DNS_UPDATE_MAX_RETRIES}...")
            try:
                list_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records?type=A&name={CF_DNS_RECORD_NAME}"
                response = requests.get(list_url, headers=headers, timeout=(CF_DNS_CONNECT_TIMEOUT, CF_DNS_READ_TIMEOUT))
                response.raise_for_status()
                result = response.json()
                if not result.get('success'):
                    raise Exception(f"查询 DNS 记录失败: {result.get('errors')}")

                existing_records = result.get('result', [])
                deletes = [{"id": rec["id"]} for rec in existing_records]
                posts = [
                    {
                        "name": CF_DNS_RECORD_NAME,
                        "type": "A",
                        "content": ip,
                        "ttl": CF_TTL,
                        "proxied": CF_PROXIED
                    }
                    for ip in dns_content_list
                ]

                batch_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records/batch"
                payload = {"deletes": deletes, "posts": posts}
                response = requests.post(batch_url, headers=headers, json=payload,
                                        timeout=(CF_DNS_CONNECT_TIMEOUT, CF_DNS_READ_TIMEOUT))
                response.raise_for_status()
                result = response.json()
                if not result.get('success'):
                    raise Exception(f"批量更新失败: {result.get('errors')}")

                success_msg = f"Cloudflare DNS 批量更新成功！已将 {CF_DNS_RECORD_NAME} 指向 {len(dns_content_list)} 个 IP。"
                print(success_msg)
                return

            except Exception as e:
                error_msg = f"[尝试 {attempt}/{DNS_UPDATE_MAX_RETRIES}] DNS 更新出错: {e}"
                print(error_msg)
                if attempt < DNS_UPDATE_MAX_RETRIES:
                    time.sleep(DNS_UPDATE_RETRY_DELAY)
                else:
                    final_error = f"Cloudflare DNS 更新失败，已重试 {DNS_UPDATE_MAX_RETRIES} 次，错误：{e}"
                    print(final_error)
                    send_wxpusher_notification(content=final_error, summary="DNS 更新失败")

    else:
        for attempt in range(1, DNS_UPDATE_MAX_RETRIES + 1):
            print(f"\n[TXT 记录更新] 尝试 {attempt}/{DNS_UPDATE_MAX_RETRIES}...")
            try:
                list_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records?type=TXT&name={CF_DNS_RECORD_NAME}"
                resp = requests.get(list_url, headers=headers, timeout=(CF_DNS_CONNECT_TIMEOUT, CF_DNS_READ_TIMEOUT))
                resp.raise_for_status()
                existing = resp.json().get('result', [])
                deletes = [{"id": rec["id"]} for rec in existing]

                posts = [
                    {
                        "name": CF_DNS_RECORD_NAME,
                        "type": "TXT",
                        "content": content,
                        "ttl": CF_TTL
                    }
                    for content in dns_content_list
                ]

                batch_url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records/batch"
                payload = {"deletes": deletes, "posts": posts}
                batch_resp = requests.post(batch_url, headers=headers, json=payload,
                                           timeout=(CF_DNS_CONNECT_TIMEOUT, CF_DNS_READ_TIMEOUT))
                batch_resp.raise_for_status()
                result = batch_resp.json()
                if not result.get('success'):
                    raise Exception(f"批量更新失败: {result.get('errors')}")

                print(f"Cloudflare TXT 记录批量更新成功！共 {len(dns_content_list)} 条记录，每条内容为一个 IP:端口。")
                return

            except Exception as e:
                error_msg = f"[尝试 {attempt}/{DNS_UPDATE_MAX_RETRIES}] TXT 更新出错: {e}"
                print(error_msg)
                if attempt < DNS_UPDATE_MAX_RETRIES:
                    time.sleep(DNS_UPDATE_RETRY_DELAY)
                else:
                    final_error = f"Cloudflare TXT 记录更新失败，已重试 {DNS_UPDATE_MAX_RETRIES} 次，错误：{e}"
                    print(final_error)
                    send_wxpusher_notification(content=final_error, summary="DNS 更新失败")

def sync_to_github():
    script_dir = os.path.dirname(os.path.abspath(__file__))

    if sys.platform == "win32":
        # 本机已实证 api.github.com 可达，直接调用已有 Contents API 路径。
        # 避免 git 三轮超时后才尝试 API，也不再执行强推历史的兜底。
        script_name = "push_api.py"
        interpreter = [sys.executable, "-X", "utf8"]
        creationflags = subprocess.CREATE_NO_WINDOW
    else:
        script_name = "git_sync.sh"
        interpreter = ["bash"]
        creationflags = 0

    script_path = os.path.join(script_dir, script_name)
    if not os.path.exists(script_path):
        print(f"未找到 {script_name}，跳过 GitHub 同步。")
        return False

    if sys.platform != "win32":
        try:
            os.chmod(script_path, 0o755)
        except Exception:
            pass

    for attempt in range(1, GITHUB_SYNC_MAX_RETRIES + 1):
        print(f"\n正在同步到 GitHub (尝试 {attempt}/{GITHUB_SYNC_MAX_RETRIES})...")
        try:
            cmd = interpreter + [script_path]
            if sys.platform == "win32":
                cmd.append(os.path.abspath(OUTPUT_FILE))
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace',
                creationflags=creationflags
            )

            try:
                stdout, stderr = process.communicate(timeout=GIT_SYNC_PROCESS_TIMEOUT)
                if process.returncode == 0:
                    if script_name == "push_api.py" and stdout.strip():
                        print(stdout.strip())
                    print("已自动推送到 GitHub。")
                    return True
                else:
                    print(f"推送失败 (退出码 {process.returncode})")
                    if stderr:
                        print(f"错误信息: {stderr.strip()}")
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                print(f"推送超时（超过 {GIT_SYNC_PROCESS_TIMEOUT} 秒）")
        except Exception as e:
            print(f"推送过程异常: {e}")

        if attempt < GITHUB_SYNC_MAX_RETRIES:
            time.sleep(GITHUB_SYNC_RETRY_DELAY)

    send_wxpusher_notification(
        content=f"GitHub 推送失败，已重试 {GITHUB_SYNC_MAX_RETRIES} 次，请检查网络或仓库状态。",
        summary="GitHub 推送失败"
    )
    print(f"已尝试 {GITHUB_SYNC_MAX_RETRIES} 次推送，均失败，请检查网络或 GitHub 仓库状态。")
    return False

def write_ip_txt(final_nodes, output_file,
                 header_enabled, header_lines,
                 footer_enabled, footer_lines,
                 perline_enabled, perline_text,
                 speed_map=None, latency_map=None,
                 http_latency_map=None, http_jitter_map=None):
    # 在同目录临时写完再替换；异常或进程中断不留下半份生产池。
    directory = os.path.dirname(os.path.abspath(output_file))
    fd, temporary = tempfile.mkstemp(prefix=".cfnb-pool-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            _write_ip_lines(f, final_nodes, header_enabled, header_lines, footer_enabled,
                            footer_lines, perline_enabled, perline_text, speed_map,
                            latency_map, http_latency_map, http_jitter_map)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, output_file)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _write_ip_lines(f, final_nodes, header_enabled, header_lines, footer_enabled,
                    footer_lines, perline_enabled, perline_text, speed_map,
                    latency_map, http_latency_map, http_jitter_map):
    if header_enabled:
        for line in header_lines:
            f.write(line + "\n")
    for node in final_nodes:
        line = node
        if IP_TXT_SHOW_BANDWIDTH and speed_map and node in speed_map:
            line += f" {speed_map[node]:.2f} Mbps"
        if IP_TXT_SHOW_HTTP_LATENCY and http_latency_map and node in http_latency_map:
            line += f" {http_latency_map[node]:.2f} ms"
        if IP_TXT_SHOW_HTTP_JITTER and http_jitter_map and node in http_jitter_map:
            line += f" {http_jitter_map[node]:.2f} ms"
        if IP_TXT_SHOW_LATENCY and latency_map and node in latency_map:
            line += f" {latency_map[node]*1000:.2f} ms"
        if perline_enabled and perline_text:
            line += perline_text
        f.write(line + "\n")
    if footer_enabled:
        for line in footer_lines:
            f.write(line + "\n")

def select_lx_reserve(measured, main_pool, slots):
    """从放宽闸门后的 LX 实测结果按速度取保底名额：与主池按 IP:port 去重、
    强制 #LX 标签（与地区标签区分，用户可在 ip.txt/订阅里直接辨认保底来源）。"""
    if slots <= 0:
        return []
    used = {n.split("#")[0] for n in main_pool}
    picked = []
    for node, speed in sorted(measured, key=lambda x: x[1], reverse=True):
        base = node.split("#")[0]
        if base in used:
            continue
        used.add(base)
        picked.append(f"{base}#LX")
        if len(picked) >= slots:
            break
    return picked

def measure_lx_reserve(main_pool):
    """良心云保底（2026-09-25 拍板）：额外名额、审查放宽 30%，但闸门与主池同源，
    只放宽数值（TCP 260ms / TLS 2.6s / 带宽 ≥0.7MB）。返回入选节点列表。"""
    if not LX_RESERVE_ENABLED:
        return []
    if not os.path.exists(LX_RESERVE_FILE):
        print(f"\n[LX保底] {LX_RESERVE_FILE} 不存在（fetch_sources 未产出或 LX 源全空），跳过保底名额。")
        return []
    with open(LX_RESERVE_FILE, encoding="utf-8", errors="ignore") as f:
        cands = [l.strip() for l in f if l.strip()]
    if not cands:
        print("\n[LX保底] 候选为空，跳过。")
        return []
    print(f"\n[LX保底] 良心云候选 {len(cands)} 个，保底名额 {LX_RESERVE_SLOTS} 个，"
          f"放宽门槛：TCP ≤{LX_RESERVE_MAX_LATENCY_MS:.0f}ms / TLS ≤{LX_RESERVE_MAX_TLS_S}s / "
          f"带宽 ≥{LX_RESERVE_MIN_BYTES} 字节")
    gated = []
    for node in cands:
        m = IP_PORT_PATTERN.match(node)
        if not m:
            continue
        ip, port = m.group(1), m.group(2)
        lat, ok = test_tcp_latency(ip, int(port), timeout=TIMEOUT, probes=TCP_PROBES)
        if not ok or lat * 1000 > LX_RESERVE_MAX_LATENCY_MS:
            continue
        gated.append(node)
    print(f"[LX保底] 过 TCP 闸 {len(gated)}/{len(cands)}")
    if not gated:
        return []
    measured = []
    with ThreadPoolExecutor(max_workers=BANDWIDTH_WORKERS) as ex:
        for node, speed in ex.map(
                lambda n: measure_bandwidth_curl(
                    n, tls_max_s=LX_RESERVE_MAX_TLS_S, min_bytes=LX_RESERVE_MIN_BYTES),
                gated):
            if speed > 0:
                measured.append((node, speed))
    print(f"[LX保底] 过带宽闸 {len(measured)}/{len(gated)}")
    return select_lx_reserve(measured, main_pool, LX_RESERVE_SLOTS)

def main(dry_run=False):
    # 0=已发布；2=链路污染；4=无合格新池；5=新池已落盘但 GitHub 失败。
    HANDSHAKE_MS.clear()
    mode_str = f"全局最优{GLOBAL_TOP_N}个" if USE_GLOBAL_MODE else f"每个国家最优{PER_COUNTRY_TOP_N}个"
    print(f"当前模式：{mode_str}，每个节点测试 {TCP_PROBES} 次 TCP 连接")
    print(f"最低成功率要求：{MIN_SUCCESS_RATE*100:.0f}%")
    print(f"IP 可用性二次筛选：{'启用' if TEST_AVAILABILITY else '禁用'}（仅对候选节点）")
    print(f"HTTP检测：{'启用' if HTTP_TEST_ENABLED else '禁用'}（仅对候选节点）")
    print(f"IPv6 客户端 IP 过滤（仅作用于DNS更新环节）：{'启用' if FILTER_IPV6_AVAILABILITY else '禁用'}")
    print(f"DNS黑名单过滤：{'启用' if FILTER_BLOCKED_COUNTRIES_ENABLED else '禁用'}，黑名单国家：{', '.join(BLOCKED_COUNTRIES)}")
    print(f"IP 风险等级过滤：{'启用' if DNS_IP_RISK_FILTER_ENABLED else '禁用'}（最高允许：{DNS_IP_RISK_MAX_LEVEL}）")
    print(f"带宽测速候选数：{BANDWIDTH_CANDIDATES}，测速文件大小：{BANDWIDTH_SIZE_MB} MB，超时：{BANDWIDTH_TIMEOUT}s"
          + (f"，TLS 建链总耗时门槛：{TLS_HANDSHAKE_MAX_S}s" if TLS_HANDSHAKE_MAX_S > 0 else "，TLS 建链总耗时门槛：关闭"))
    if FILTER_COUNTRIES_ENABLED:
        print(f"前置白名单过滤：启用，仅保留：{', '.join(ALLOWED_COUNTRIES)}")

    nodes = []
    for source in ADDITIONAL_SOURCES:
        if not source.get("enabled", True):
            continue
        url = source.get("url")
        if not url:
            continue
        v2_nodes = fetch_additional_source(url)
        if v2_nodes:
            seen = set()
            for n in nodes:
                seen.add(n.split('#')[0])
            for n in v2_nodes:
                key = n.split('#')[0]
                if key not in seen:
                    seen.add(key)
                    nodes.append(n)
    print(f"合并后总计 {len(nodes)} 个节点。")

    token_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), IP_CALIBRATION_TOKEN_FILE)
    cache_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), IP_CALIBRATION_CACHE_FILE)
    calibrate_regions(nodes, token_file, cache_file)

    if PRE_FILTER_PORT_ENABLED:
        before = len(nodes)
        nodes = [n for n in nodes if n.split(':')[1].split('#')[0] in PRE_FILTER_PORTS]
        after = len(nodes)
        ports_display = ', '.join(PRE_FILTER_PORTS)
        print(f"前置端口过滤（仅保留端口 {ports_display}）：{before} -> {after} 个节点")
        if not nodes:
            print("前置端口过滤后无任何节点，退出程序。")
            return 4

    if PRE_FILTER_BLOCKED_ENABLED and PRE_FILTER_BLOCKED_COUNTRIES:
        before = len(nodes)
        blocked_set = set(PRE_FILTER_BLOCKED_COUNTRIES)
        nodes = [n for n in nodes if n.split('#')[-1].split()[0].upper() not in blocked_set]
        after = len(nodes)
        print(f"前置黑名单过滤：{before} -> {after} 个节点（已屏蔽：{', '.join(sorted(blocked_set))}）")
        if not nodes:
            print("前置黑名单过滤后无任何节点，退出程序。")
            return 4

    if not nodes:
        print("没有获取到任何有效节点，退出。")
        return 4

    if FILTER_COUNTRIES_ENABLED and ALLOWED_COUNTRIES:
        before = len(nodes)
        allowed_set = {c.upper() for c in ALLOWED_COUNTRIES}
        filtered_nodes = []
        for node in nodes:
            parts = node.split('#')
            if len(parts) == 2 and parts[1].split()[0].upper() in allowed_set:
                filtered_nodes.append(node)
        nodes = filtered_nodes
        after = len(nodes)
        print(f"\n国家过滤（测试前）：{before} -> {after} 个节点（允许国家：{', '.join(allowed_set)}）")
        if not nodes:
            print("过滤后无任何节点，退出程序。")
            return 4

    total = len(nodes)
    print(f"开始 TCP 连接测试（超时 {TIMEOUT}s，并发 {MAX_WORKERS}）...")

    results = []
    completed = 0
    last_print = time.time()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_node, node): node for node in nodes}
        for future in as_completed(futures):
            completed += 1
            res = future.result()
            if res:
                results.append(res)
            now = time.time()
            if now - last_print >= PROGRESS_PRINT_INTERVAL or completed == total:
                print(f"\r进度：{completed}/{total} ({(completed/total)*100:.1f}%)", end="", flush=True)
                last_print = now

    print("\nTCP 测试完成！")
    if not results:
        print("没有通过成功率筛选的节点，请检查网络或降低 MIN_SUCCESS_RATE。")
        return 4

    results.sort(key=lambda x: (-x[3], x[1]))
    latency_map = {node: lat for node, lat, _, _ in results}

    if USE_GLOBAL_MODE:
        # 候选池按"CF 官方段 / 他人反代"混合取（2026-09-18 教训：官方段全占候选会集体倒在
        # 带宽关——随机采样的官方 IP 多数很慢——池子从 30 塌到 7；改两类各半，让实测裁决）
        _nets = load_cf_nets()
        # 在岗补位：上轮入池的 IP 也进候选一起测速（性能退化会被新 IP 挤掉——"多一次机会"而非"保位"）
        _inc_add = []
        _hist = _load_pool_history()
        if _hist:
            _inc_nodes = list(dict.fromkeys(
                list(_hist[-1].get("nodes") or []) +
                [f"{ip}:443" for ip in (_hist[-1].get("ips") or [])]))
            _in_results = {r[0] for r in results}
            _inc_add = [n for n in _inc_nodes
                        if n not in _in_results and n.split(":")[0] in {r[0].split(":")[0] for r in results}][:10]
        if _nets:
            _off = [n for n, _, _, _ in results if is_cf_official(n.split(":")[0], _nets)]
            _prox = [n for n, _, _, _ in results if not is_cf_official(n.split(":")[0], _nets)]
            _half = BANDWIDTH_CANDIDATES // 2
            candidates = _off[:_half] + _prox[:_half] + _inc_add
            print(f"\n候选池混合取：官方 {min(len(_off),_half)} + 反代 {min(len(_prox),_half)}"
                  f" + 在岗补位 {len(_inc_add)} = {len(candidates)} 个"
                  f"（可用候选 官方 {len(_off)} / 反代 {len(_prox)}）")
        else:
            candidates = [node for node, _, _, _ in results[:BANDWIDTH_CANDIDATES]] + _inc_add
            print(f"\nTCP 最优前 {len(candidates)-len(_inc_add)} 个 + 在岗 {len(_inc_add)} 进入候选池。")
    else:
        country_nodes = defaultdict(list)
        for node_str, lat, country, succ in results:
            country_nodes[country].append((node_str, lat, succ))

        total_countries = len(country_nodes)
        base_limit = max(1, BANDWIDTH_CANDIDATES // total_countries)
        candidates = []
        for country, nodes in country_nodes.items():
            nodes_sorted = sorted(nodes, key=lambda x: (-x[2], x[1]))
            limit = min(len(nodes_sorted), base_limit)
            for node_str, lat, succ in nodes_sorted[:limit]:
                candidates.append(node_str)
        print(f"\n各国家候选池分配：共 {total_countries} 个国家，每国最多 {base_limit} 个候选，总计 {len(candidates)} 个节点进入候选池。")

    if not candidates:
        print("没有候选节点，退出。")
        return 4

    # CF 官方段跳过 proxyip 可用性检测（2026-09-18 教训：该 API 验的是"这 IP 能不能当开放代理"，
    # 真 CF 边缘必然判失败 → 官方段被全灭只剩反代）；官方段改由带宽测试裁决
    # （测速走 --resolve speed.cloudflare.com，服务不了我们 zone 的 IP 拿不到 1MB，自然被淘汰）。
    _nets_av = load_cf_nets()
    if TEST_AVAILABILITY and _nets_av:
        _off_c = [c for c in candidates if is_cf_official(c.split(":")[0], _nets_av)]
        _px_c = [c for c in candidates if not is_cf_official(c.split(":")[0], _nets_av)]
        print("[可用性豁免] 官方段 %d 个跳过 proxyip 检测，只验反代 %d 个" % (len(_off_c), len(_px_c)))
        _px_passed, _px_info, _px_exit = availability_filter_with_retry(_px_c)
        candidates_after_availability = _off_c + list(_px_passed)
        avail_ip_info, avail_exit_details = dict(_px_info), dict(_px_exit)
        print(f"可用性合计通过 {len(candidates_after_availability)} 个"
              f"（官方豁免 {len(_off_c)} + 反代实测 {len(_px_passed)}）")
    else:
        candidates_after_availability, avail_ip_info, avail_exit_details = availability_filter_with_retry(candidates)
    candidates_after_http, http_latency_map, http_jitter_map = http_server_filter(candidates_after_availability, cfg)

    bw_results = []
    for attempt in range(1, BANDWIDTH_RETRY_MAX + 1):
        print(f"\n[带宽测速] 第 {attempt} 轮测试...")
        bw_results = bandwidth_filter(candidates_after_http)
        if bw_results:
            break
        if attempt < BANDWIDTH_RETRY_MAX:
            print(f"本轮测速无有效结果，等待 {BANDWIDTH_RETRY_DELAY} 秒后重试...")
            time.sleep(BANDWIDTH_RETRY_DELAY)

    if not bw_results:
        print("\n带宽测速多次重试仍无有效结果，保留旧池；不发布未经带宽验证的 TCP 节点。")
        send_wxpusher_notification(
            content=f"带宽测速经 {BANDWIDTH_RETRY_MAX} 轮尝试后仍无有效结果，本轮不写入、不发布，保留旧池。",
            summary="带宽测速全部失败"
        )
        return 4
    else:
        # ---- 延迟硬门槛（用户 2026-09-16 要求：最终 IP 的 TCP 延迟不超过 200ms）----
        if MAX_TCP_LATENCY_MS > 0:
            _kept = [(n, s) for n, s in bw_results
                     if latency_map.get(n, 999.0) * 1000 <= MAX_TCP_LATENCY_MS]
            if _kept:
                _dropped = len(bw_results) - len(_kept)
                if _dropped:
                    print(f"\n[延迟门槛] ≤{MAX_TCP_LATENCY_MS}ms 保留 {len(_kept)}/{len(bw_results)}"
                          f"（淘汰 {_dropped} 个高延迟节点）")
                bw_results = _kept
            else:
                print(f"\n[延迟门槛] 无节点满足 ≤{MAX_TCP_LATENCY_MS}ms，保留旧池，不放宽硬门槛。")
                return 4

        speed_map = {node: speed for node, speed in bw_results}
        # ---- 综合评分：按配置权重（当前速度 60% + 延迟 40%）归一化后加权----
        # 排序用的"延迟"= TCP 延迟 + TLS 握手（HANDSHAKE_MS）：手机 app 显示的就是这两段之和，
        # 实测差值就在这（TCP 65–85ms / app 167–279ms）。门槛仍只卡 TCP（门槛管线路、排序管体感）。
        def _eff_lat_ms(node):
            base = latency_map.get(node, 999.0) * 1000
            return base + HANDSHAKE_MS.get(node, 0)
        _speeds = [s for _, s in bw_results]
        _lats = [_eff_lat_ms(n) for n, _ in bw_results]
        smin, smax = min(_speeds), max(_speeds)
        lmin, lmax = min(_lats), max(_lats)
        # 历史存活加分：近 STABILITY_WINDOW 轮反复进池的 IP 优先（抗"一天就死"的客观衰减）
        _hist = _load_pool_history()
        _stab, _stab_hits = {}, 0
        if STABILITY_WINDOW > 0 and STABILITY_BONUS > 0 and _hist:
            _recent = _hist[-STABILITY_WINDOW:]
            for node, _s in bw_results:
                _ip = node.split(":")[0]
                _cnt = sum(1 for r in _recent if _ip in (r.get("ips") or []))
                if _cnt:
                    _stab[node] = min(_cnt, STABILITY_WINDOW) / float(STABILITY_WINDOW)
                    _stab_hits += 1
            if _stab_hits:
                print(f"\n[存活加分] 近 {len(_recent)} 轮里进过池的候选 {_stab_hits} 个，"
                      f"最高加 {STABILITY_BONUS*100:.0f}% 分（历史文件 {os.path.basename(POOL_HISTORY_FILE)}）")
        scored_nodes = []
        for node, speed in bw_results:
            lat_ms = _eff_lat_ms(node)
            s_norm = 1.0 if smax == smin else (speed - smin) / (smax - smin)
            l_norm = 1.0 if lmax == lmin else (lmax - lat_ms) / (lmax - lmin)
            score = (SCORE_SPEED_WEIGHT * s_norm + SCORE_LATENCY_WEIGHT * l_norm
                     + STABILITY_BONUS * _stab.get(node, 0.0))
            http_lat = http_latency_map.get(node, None)
            scored_nodes.append((node, score, speed, lat_ms / 1000.0,
                                 http_lat if http_lat is not None else 999999.0))

        scored_nodes.sort(key=lambda x: x[1], reverse=True)
        score_map = {item[0]: item[1] for item in scored_nodes}

        _resv_intent = {}          # 国家模式无备胎意图；全局模式在下方按需覆盖
        if USE_GLOBAL_MODE:
            if REGION_RESERVE_N > 0:
                _regions = {}
                for _it in scored_nodes:
                    _r = _it[0].split("#")[-1] if "#" in _it[0] else "?"
                    _regions[_r] = _regions.get(_r, 0) + 1
                _dom = max(_regions, key=lambda r: _regions[r]) if _regions else "-"
                if len(_regions) > 1:
                    _resv = {r: min(REGION_RESERVE_N, c) for r, c in _regions.items() if r != _dom}
                    _resv_intent = _resv
                    print(f"\n[地区备胎] 主流地区={_dom}；为其余地区保底 {_resv}")
            # 终选两层职责分开，避免互相抵消：
            #   配比（CF_OFFICIAL_RATIO>0）：先按"官方段/他人反代"取，再交地区备胎
            #   纯分数（=0，2026-09-18 用户定）：完整候选直接交地区备胎
            # 关键：apply_region_reserve 必须拿到比 top_n 更大的输入，否则它只能重排、
            #       救不回池外的次优地区节点——那"保底"就是空话（本轮实测踩过）。
            _head = GLOBAL_TOP_N + max(0, REGION_RESERVE_N) * 2
            if CF_OFFICIAL_RATIO > 0:
                _balanced, _n_off = pick_balanced(scored_nodes, _head, CF_OFFICIAL_RATIO, load_cf_nets())
                _bset = set(_balanced)
                _bsub = [it for it in scored_nodes if it[0] in _bset]
                print(f"\n[配比] 官方段 {_n_off} + 他人反代 {len(_balanced)-_n_off} = {len(_balanced)}"
                      f"（目标占比 {CF_OFFICIAL_RATIO*100:.0f}%，含备胎余量，终取 {GLOBAL_TOP_N}）")
                final_selected = apply_region_reserve(_bsub, GLOBAL_TOP_N, REGION_RESERVE_N)
            else:
                print(f"\n[纯分数] 排序键 = 速度 {SCORE_SPEED_WEIGHT:.0%} + 延迟 {SCORE_LATENCY_WEIGHT:.0%}"
                      f"（延迟 = TCP + TLS 握手）；不强制官方/反代配比，由实测自己胜出")
                final_selected = apply_region_reserve(scored_nodes, GLOBAL_TOP_N, REGION_RESERVE_N)
            # 在岗优先（治"每轮大换血"）：上轮入池且本轮仍通过全部闸门的先占位，剩余名额才按分数补。
            # 2026-09-18 修：原来这里无条件 merge_incumbents(ranked_all,...) 会拿全局前 N
            #   覆盖掉 pick_balanced 的 50:50 配比（静默 bug）。改为仅在开启在岗保位时才动终选。
            if INCUMBENT_RATIO > 0:
                _inc_keys = incumbent_keys(_hist or _load_pool_history(), 1)
                final_selected = merge_incumbents([it[0] for it in scored_nodes], _inc_keys,
                                                   GLOBAL_TOP_N, INCUMBENT_RATIO)
                _kept = len(set(n.split("#")[0] for n in final_selected) & _inc_keys)
                print("[在岗优先] 在岗锁定 %.0f%% 重排完成（保留 %d 个）" % (INCUMBENT_RATIO * 100, _kept))
        else:
            country_scored = defaultdict(list)
            for item in scored_nodes:
                node, score, speed, tcp_lat, http_lat = item
                country = node.split('#')[-1] if '#' in node else ''
                if country:
                    country_scored[country].append(item)
            final_selected = []
            for country, items in country_scored.items():
                items.sort(key=lambda x: x[1], reverse=True)
                for item in items[:PER_COUNTRY_TOP_N]:
                    final_selected.append(item[0])
            score_dict = {item[0]: item[1] for item in scored_nodes}
            final_selected.sort(key=lambda n: score_dict.get(n, 0), reverse=True)

        # ---- 用实测落地国家纠正地区标签（零额外请求，官方段采样条目预标 NRT）----
        allowed = set(ALLOWED_COUNTRIES) if FILTER_COUNTRIES_ENABLED else None
        final_selected, dropped = relabel_by_exit(final_selected, [it[0] for it in scored_nodes], avail_exit_details, allowed)
        remap_node_metrics(final_selected, speed_map, latency_map, HANDSHAKE_MS,
                           http_latency_map, http_jitter_map, score_map)
        if dropped:
            print(f"\n[落地校正] 修正地区标签 {len(dropped)} 个（不删除已通过节点）：{', '.join(dropped[:6])}")

        print("\n================ 最终优选节点 ================")
        # 终池真实构成（口径以这一行为准：上面的"保底/配比"都是意图，可能被实测候选不足打破）
        _nets_f = load_cf_nets()
        _reg_f = {}
        for _n in final_selected:
            _r = _n.split("#")[-1] if "#" in _n else "?"
            _reg_f[_r] = _reg_f.get(_r, 0) + 1
        _noff = sum(1 for _n in final_selected
                    if _nets_f and is_cf_official(_n.split(":")[0], _nets_f))
        print("[终池构成] 地区 %s｜CF 官方段 %d/%d" % (_reg_f, _noff, len(final_selected)))
        # 意图 vs 实际若有差额，必须说明原因：地区备胎作用在"源标签"上，
        # 而 relabel_by_exit 之后以真实落地国为准——CF anycast 同一批 IP 常被标多地区
        # 却从同一个 PoP 出口，保底名额会被实测"收敛"掉，这是数据真相而非漏保。
        if _reg_f and _resv_intent:
            _dom_f = max(_reg_f, key=lambda r: _reg_f[r])
            _gap = {r: (want, _reg_f.get(r, 0)) for r, want in _resv_intent.items()
                    if _reg_f.get(r, 0) < want}
            if _gap:
                print("        ↳ 备胎差额 %s（请求→实际）：这些节点的真实落地被校正为 %s，"
                      "源标签不可信，非逻辑漏保" % (_gap, _dom_f))
        for i, node in enumerate(final_selected, 1):
            speed = speed_map.get(node, 0)
            tcp_lat = latency_map.get(node, float('inf'))
            http_lat = http_latency_map.get(node, None)
            http_jitter = http_jitter_map.get(node, None)
            line = f"{i}. {node} 速度 {speed:.2f} Mbps"
            if score_map:
                line += f" 综合 {score_map.get(node, 0):.2f}"
            if http_lat is not None:
                line += f" 延迟 {http_lat:.2f} ms"
            if http_jitter is not None:
                line += f" 抖动 {http_jitter:.2f} ms"
            if tcp_lat != float('inf'):
                line += f" 延迟 {tcp_lat*1000:.2f} ms"
            hs = HANDSHAKE_MS.get(node)
            if hs:
                line += f" TLS握 {hs} ms"
            print(line)

    # ---- 小池硬保险（2026-09-18）：池子过小宁可不覆盖、不推送，保住线上可用池 ----
    if len(final_selected) < MIN_POOL_NODES:
        print("[小池保险] 本轮只选出 %d 个（< %d），拒绝覆盖 %s 与 GitHub 推送；请检查源/链路后重跑。"
              % (len(final_selected), MIN_POOL_NODES, OUTPUT_FILE))
        return 4

    # ---- 链路体检闸门 ----
    # 直连场景下境外节点不可能出现个位数 ms 的 TCP 延迟；中位数 <10ms 说明本轮流量
    # 被 TUN/代理劫持（TUN 会立刻 accept），测出的"精英"只在代理路径上可达，
    # 手机直连必然全超时（2026-09-15 与 09-16 两次事故同一成因）→ 拒绝落盘、拒绝推送。
    _lats = sorted(latency_map[n] * 1000 for n in final_selected if n in latency_map)
    if _lats:
        _med = _lats[len(_lats) // 2]
        if _med < 10.0:
            print(f"\n[链路体检] 中位 TCP 延迟仅 {_med:.2f} ms —— 境外节点不可能这么低，"
                  f"判定本轮被代理/TUN 劫持：跳过写入 {OUTPUT_FILE} 与 GitHub 推送。"
                  f"（请关掉代理后重跑；先跑 e2e_test.py env 自检）")
            return 2

    # ---- 良心云保底名额（主池定稿后、落盘前；不挤占主池名额也不进链路体检中位数）----
    lx_picked = measure_lx_reserve(final_selected)
    if lx_picked:
        print("[LX保底] 本轮入选 %d 个：%s" % (len(lx_picked), " ".join(lx_picked)))
        final_selected = final_selected + lx_picked

    if dry_run:
        print(f"\n[不发布验证] {len(final_selected)} 个节点（含 LX 保底 {len(lx_picked)} 个）通过全部闸门；不改 ip.txt、历史、DNS 或 GitHub。")
        return 0

    write_ip_txt(final_selected, OUTPUT_FILE,
                 AD_HEADER_ENABLED, AD_HEADER_LINES,
                 AD_FOOTER_ENABLED, AD_FOOTER_LINES,
                 AD_PERLINE_ENABLED, AD_PERLINE_TEXT,
                 speed_map=speed_map,
                 latency_map=latency_map,
                 http_latency_map=http_latency_map,
                 http_jitter_map=http_jitter_map)
    print(f"\n结果已保存到 {OUTPUT_FILE}（共 {len(final_selected)} 个节点）")

    # ---- 存活率（真实建链复测，不是"入池重叠"）----
    # 2026-09-18 教训：先用"上轮入池∩本轮入池"当存活率，得到 0% —— 那是相对排名+候选重采样
    # 造成的换血假象，老池 30 个里实际只死 6 个。真实死亡率必须对老池逐个建链复测。
    _prev = _load_pool_history()
    if _prev:
        _pnodes = _prev[-1].get("nodes") or [ip + ":443" for ip in (_prev[-1].get("ips") or [])]
        if _pnodes:
            _alive, _dead = _probe_alive(_pnodes)
            _now_keys = {n.split("#")[0] for n in final_selected}
            _carry = len({n.split("#")[0] for n in _alive} & _now_keys)
            print(f"[存活率] 上轮 {len(_pnodes)} 个：真实仍可建链 {len(_alive)} 个"
                  f"（死 {len(_dead)} 个，{100.0*len(_dead)/len(_pnodes):.0f}%），"
                  f"其中 {_carry} 个本轮继续在岗；上轮时间 {_prev[-1].get('ts','?')}")
            if _dead:
                print(f"         已死: {' '.join(_dead[:12])}{' ...' if len(_dead)>12 else ''}")
    _save_pool_history(final_selected)

    ip_list = [node.split(':')[0] for node in final_selected]

    batch_update_cloudflare_dns(
        ip_list,
        ip_info=avail_ip_info,
        full_bw_results=bw_results,
        target_count=None,
        latency_map=latency_map,
        http_latency_map=http_latency_map,
        http_jitter_map=http_jitter_map
    )

    return 0 if sync_to_github() else 5

if __name__ == "__main__":
    import atexit
    parser = argparse.ArgumentParser(description="CFNB 优选与发布")
    parser.add_argument("--dry-run", action="store_true", help="真实测速与筛选，只显示结果，不写生产池或发布")
    args = parser.parse_args()

    enable_log = ENABLE_LOGGING
    log_filename = LOG_FILE

    if enable_log:
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            log_path = os.path.join(script_dir, log_filename)
            log_f = open(log_path, "w", encoding="utf-8")
            print("日志已启用，输出将保存到 " + log_path)
        except Exception as e:
            print(f"无法打开日志文件 {log_path}: {e}")
            log_f = None
        else:
            class _Tee:
                def __init__(self, *files):
                    self.files = files
                def write(self, obj):
                    for f in self.files:
                        f.write(obj)
                        f.flush()
                def flush(self):
                    for f in self.files:
                        f.flush()
            sys.stdout = _Tee(sys.stdout, log_f)

            def _close_log():
                try:
                    sys.stdout = sys.__stdout__
                    log_f.close()
                except Exception:
                    pass
            atexit.register(_close_log)

    sys.exit(main(dry_run=args.dry_run))
