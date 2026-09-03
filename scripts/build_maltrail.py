#!/usr/bin/env python3
"""
build_maltrail.py

下载 maltrail 的 IP 黑名单和域名黑名单，去重排序后，
合并生成单一的 sing-box rule-set 源文件 maltrail.json，
再调用 sing-box 将其编译为二进制规则集 maltrail.srs。

用法:
    python3 build_maltrail.py \
        --ip-url https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/1.txt \
        --domain-source trails \
        --output-dir rules \
        --sing-box-bin sing-box

说明:
    stamparm/aux 仓库（原来托管 maltrail-malware-domains.txt 的地方）已下线。
    静态威胁情报数据现已统一发布在 stamparm/trails 仓库的 Release 中
    （trails.csv.gz + trails.csv.sha256）。--domain-source 默认值 "trails"
    会自动下载最新 Release、校验 sha256、解析出纯域名指标。

    如果仍想从某个普通的纯域名文本文件 URL 获取（旧行为），把 --domain-source
    设为该 URL（以 http:// 或 https:// 开头）即可；设为本地文件路径则会直接读取该文件。
"""

import argparse
import csv
import gzip
import hashlib
import ipaddress
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

TRAILS_RELEASE_BASE = "https://github.com/stamparm/trails/releases/latest/download"
TRAILS_CSV_GZ_URL = f"{TRAILS_RELEASE_BASE}/trails.csv.gz"
TRAILS_SHA256_URL = f"{TRAILS_RELEASE_BASE}/trails.csv.sha256"

# 合法域名（不含协议/路径/端口），且排除纯 IPv4 地址
DOMAIN_RE = re.compile(
    r"^(?!\d{1,3}(\.\d{1,3}){3}$)"
    r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def download_bytes(url: str, timeout: int = 60) -> bytes:
    """下载 url 内容并以 bytes 形式返回"""
    print(f"⬇️  正在下载: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def download_text(url: str) -> str:
    """下载 url 内容并以文本形式返回"""
    return download_bytes(url).decode("utf-8", errors="ignore")


def fetch_trails_domains(classes: list[str], skip_verify: bool = False) -> list[str]:
    """
    从 stamparm/trails 仓库最新 Release 下载 trails.csv.gz，
    （可选）校验 sha256，解析出属于指定威胁等级、且本身是纯域名格式的指标。
    """
    csv_gz = download_bytes(TRAILS_CSV_GZ_URL)

    if not skip_verify:
        print(f"⬇️  正在下载校验文件: {TRAILS_SHA256_URL}")
        expected_sha256 = download_bytes(TRAILS_SHA256_URL).decode().strip().split()[0]
        print("🔐 正在校验 sha256 ...")
        csv_bytes = gzip.decompress(csv_gz)
        actual_sha256 = hashlib.sha256(csv_bytes).hexdigest()
        if actual_sha256 != expected_sha256:
            print(
                f"❌ sha256 校验失败: 期望 {expected_sha256}，实际 {actual_sha256}",
                file=sys.stderr,
            )
            sys.exit(1)
        print("✅ sha256 校验通过")
    else:
        csv_bytes = gzip.decompress(csv_gz)

    wanted_classes = {f"({c.strip()})" for c in classes if c.strip()}
    print(f"🔎 正在解析 trails.csv（保留等级: {', '.join(sorted(wanted_classes))}）...")

    domains: set[str] = set()
    total = 0
    text = csv_bytes.decode("utf-8", errors="replace")
    reader = csv.reader(text.splitlines())
    for row in reader:
        total += 1
        if len(row) < 2:
            continue
        indicator = row[0].strip()
        cls = row[1]
        if not any(tag in cls for tag in wanted_classes):
            continue
        if "/" in indicator or ":" in indicator:
            # host/path、URL、IP:port 等非纯域名指标，跳过
            continue
        if DOMAIN_RE.match(indicator):
            domains.add(indicator.lower())

    print(f"   共扫描 {total} 行，提取到 {len(domains)} 个唯一域名")
    return sorted(domains)


def resolve_domain_lines(source: str, classes: list[str], skip_verify: bool = False) -> list[str]:
    """
    根据 --domain-source 的值决定如何获取域名列表：
      - "trails"（默认）：从 stamparm/trails 最新 Release 下载并解析
      - http:// 或 https:// 开头：按纯文本文件下载（兼容旧的 maltrail-malware-domains.txt 用法）
      - 其他：当作本地文件路径读取
    """
    if source == "trails":
        return fetch_trails_domains(classes, skip_verify=skip_verify)
    if source.startswith("http://") or source.startswith("https://"):
        return clean_lines(download_text(source))
    print(f"📄 正在读取本地域名文件: {source}")
    return clean_lines(Path(source).read_text(encoding="utf-8", errors="ignore"))


def clean_lines(raw: str) -> list[str]:
    """按行拆分，去除空白行和首尾空白"""
    return [line.strip() for line in raw.splitlines() if line.strip()]


def parse_ip_networks(lines: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """
    将 IP / CIDR 字符串列表解析为 ipaddress 网络对象，并按字符串去重。
    支持纯 IP（如 1.2.3.4）以及 CIDR（如 10.0.0.0/24）两种格式。
    无法解析的行会被跳过并给出警告。
    """
    unique = sorted(set(lines))  # 先按字符串去重，避免重复解析
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in unique:
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            print(f"⚠️  跳过无法解析的 IP/CIDR: {item}", file=sys.stderr)
    return networks


def sort_ip_networks(networks: list) -> list[str]:
    """按数值大小排序（IPv4 在前，IPv6 在后），返回字符串形式"""
    ordered = sorted(networks, key=lambda net: (net.version, net.network_address, net.prefixlen))
    return [str(net) if net.prefixlen != net.max_prefixlen else str(net.network_address) for net in ordered]


def aggregate_ip_networks(networks: list) -> list:
    """
    使用 ipaddress.collapse_addresses 聚合相邻且边界对齐的 IP/CIDR。
    这是无损合并：只有当若干地址恰好能拼成一个更大的连续 CIDR 块时才会合并，
    不会引入名单之外的地址，因此不会带来误拦截风险，只是减少规则条数。
    """
    ipv4 = [n for n in networks if n.version == 4]
    ipv6 = [n for n in networks if n.version == 6]

    collapsed: list = []
    if ipv4:
        collapsed.extend(ipaddress.collapse_addresses(ipv4))
    if ipv6:
        collapsed.extend(ipaddress.collapse_addresses(ipv6))
    return collapsed


def sort_dedup_ips(lines: list[str], aggregate: bool = True) -> list[str]:
    """
    对 IP / CIDR 列表去重、（可选）聚合相邻网段，并按数值大小排序。
    返回字符串列表，纯 /32 或 /128 的条目会以单个 IP 的形式输出（不带 /32 后缀）。
    """
    networks = parse_ip_networks(lines)
    if aggregate:
        before = len(networks)
        networks = aggregate_ip_networks(networks)
        print(f"   聚合前 {before} 条，聚合后 {len(networks)} 条")
    return sort_ip_networks(networks)


def sort_dedup_domains(lines: list[str]) -> list[str]:
    """对域名列表去重并按字典序排序"""
    return sorted(set(lines))


def build_ruleset_json(domains: list[str], ips: list[str]) -> dict:
    """构建 sing-box rule-set 的 JSON 结构（version 5，domain_suffix + ip_cidr 合并在同一条规则里）"""
    return {
        "version": 5,
        "rules": [
            {
                "domain_suffix": domains,
                "ip_cidr": ips,
            }
        ],
    }


def compile_ruleset(sing_box_bin: str, json_path: Path, srs_path: Path) -> None:
    """调用 sing-box 将 json 规则集编译为二进制 .srs 文件"""
    print(f"🔨 正在编译 {srs_path.name} ...")
    subprocess.run(
        [sing_box_bin, "rule-set", "compile", str(json_path), "-o", str(srs_path)],
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="构建合并后的 maltrail sing-box 规则集")
    parser.add_argument(
        "--ip-url",
        default="https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/1.txt",
        help="IP 黑名单来源 URL",
    )
    parser.add_argument(
        "--domain-source",
        default="trails",
        help=(
            "域名黑名单来源。默认 'trails'：从 stamparm/trails 最新 Release 下载并解析"
            "（stamparm/aux 仓库已下线）。也可传入 http(s):// 开头的纯文本文件 URL，"
            "或本地文件路径。"
        ),
    )
    parser.add_argument(
        "--domain-classes",
        default="malware,malicious",
        help="使用 --domain-source trails 时保留的威胁等级，逗号分隔，可选 malware,malicious,suspicious",
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="使用 --domain-source trails 时跳过 sha256 校验（不建议）",
    )
    parser.add_argument(
        "--domain-url",
        default=None,
        help="[已废弃] 等价于 --domain-source，仅为向后兼容保留",
    )
    parser.add_argument("--output-dir", default="rules", help="输出目录")
    parser.add_argument("--output-name", default="maltrail", help="输出文件名（不含扩展名）")
    parser.add_argument("--sing-box-bin", default="sing-box", help="sing-box 可执行文件路径")
    parser.add_argument(
        "--skip-compile",
        action="store_true",
        help="仅生成 JSON，不调用 sing-box 编译二进制文件（调试用）",
    )
    parser.add_argument(
        "--no-aggregate-ips",
        dest="aggregate_ips",
        action="store_false",
        help="关闭 IP 聚合，保留原始的逐条 IP/CIDR（默认开启聚合）",
    )
    parser.set_defaults(aggregate_ips=True)
    args = parser.parse_args()

    if args.domain_url:
        print("⚠️  --domain-url 已废弃，请改用 --domain-source（本次运行按 --domain-url 的值处理）")
        args.domain_source = args.domain_url

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / f"{args.output_name}.json"
    srs_path = output_dir / f"{args.output_name}.srs"

    # 1. 下载
    ip_raw = download_text(args.ip_url)
    domain_classes = [c for c in args.domain_classes.split(",") if c.strip()]
    domain_lines = resolve_domain_lines(
        args.domain_source, domain_classes, skip_verify=args.skip_verify
    )

    # 2. 去重排序
    print("🔤 正在对 IP 列表去重排序...")
    ips = sort_dedup_ips(clean_lines(ip_raw), aggregate=args.aggregate_ips)
    print(f"   共 {len(ips)} 条 IP/CIDR")

    print("🔤 正在对域名列表去重排序...")
    domains = sort_dedup_domains(domain_lines)
    print(f"   共 {len(domains)} 条域名")

    # 3. 生成合并后的 JSON
    ruleset = build_ruleset_json(domains, ips)
    json_path.write_text(
        json.dumps(ruleset, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"✅ 已生成 {json_path}")

    # 4. 编译为二进制 .srs
    if not args.skip_compile:
        compile_ruleset(args.sing_box_bin, json_path, srs_path)
        print(f"✅ 已生成 {srs_path}")
    else:
        print("⏭️  已跳过编译步骤 (--skip-compile)")


if __name__ == "__main__":
    main()
