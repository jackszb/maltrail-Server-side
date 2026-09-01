#!/usr/bin/env python3
"""
build_maltrail.py

下载 maltrail 的 IP 黑名单和域名黑名单，去重排序后，
合并生成单一的 sing-box rule-set 源文件 maltrail.json，
再调用 sing-box 将其编译为二进制规则集 maltrail.srs。

用法:
    python3 build_maltrail.py \
        --ip-url https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/1.txt \
        --domain-url https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt \
        --output-dir rules \
        --sing-box-bin sing-box
"""

import argparse
import ipaddress
import json
import subprocess
import sys
import urllib.request
from pathlib import Path


def download_text(url: str) -> str:
    """下载 url 内容并以文本形式返回"""
    print(f"⬇️  正在下载: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", errors="ignore")


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
        "--domain-url",
        default="https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt",
        help="域名黑名单来源 URL",
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

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / f"{args.output_name}.json"
    srs_path = output_dir / f"{args.output_name}.srs"

    # 1. 下载
    ip_raw = download_text(args.ip_url)
    domain_raw = download_text(args.domain_url)

    # 2. 去重排序
    print("🔤 正在对 IP 列表去重排序...")
    ips = sort_dedup_ips(clean_lines(ip_raw), aggregate=args.aggregate_ips)
    print(f"   共 {len(ips)} 条 IP/CIDR")

    print("🔤 正在对域名列表去重排序...")
    domains = sort_dedup_domains(clean_lines(domain_raw))
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
