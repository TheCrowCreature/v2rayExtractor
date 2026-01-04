import base64
import json
import logging
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List, Dict
import urllib.parse
import pycountry
import requests
from bs4 import BeautifulSoup
import shutil
import telegram_sender

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ROOT_DIR = Path(__file__).parent.parent
SUB_CHECKER_DIR = Path(__file__).parent / "sub-checker"

TELEGRAM_URLS = [
    "https://t.me/s/prrofile_purple", "https://t.me/s/v2line", "https://t.me/s/v2ray1_ng",
    "https://t.me/s/v2ray_swhil", "https://t.me/s/v2rayng_fast", "https://t.me/s/v2rayng_vpnrog",
    "https://t.me/s/v2raytz", "https://t.me/s/vmessorg", "https://t.me/s/ISVvpn",
    "https://t.me/s/forwardv2ray", "https://t.me/s/PrivateVPNs", "https://t.me/s/VlessConfig",
    "https://t.me/s/V2pedia", "https://t.me/s/v2rayNG_Matsuri", "https://t.me/s/proxystore11",
    "https://t.me/s/DirectVPN", "https://t.me/s/OutlineVpnOfficial", "https://t.me/s/networknim",
    "https://t.me/s/weiten", "https://t.me/s/MsV2ray", "https://t.me/s/foxrayiran",
    "https://t.me/s/DailyV2RY", "https://t.me/s/yaney_01", "https://t.me/s/EliV2ray",
    "https://t.me/s/ServerNett", "https://t.me/s/v2rayng_fa2", "https://t.me/s/v2rayng_org",
    "https://t.me/s/V2rayNGvpni", "https://t.me/s/v2rayNG_VPNN", "https://t.me/s/v2_vmess",
    "https://t.me/s/FreeVlessVpn", "https://t.me/s/vmess_vless_v2rayng", "https://t.me/s/freeland8",
    "https://t.me/s/vmessiran", "https://t.me/s/V2rayNG3", "https://t.me/s/ShadowsocksM",
    "https://t.me/s/ShadowSocks_s", "https://t.me/s/VmessProtocol", "https://t.me/s/Easy_Free_VPN",
    "https://t.me/s/V2Ray_FreedomIran", "https://t.me/s/V2RAY_VMESS_free", "https://t.me/s/v2ray_for_free",
    "https://t.me/s/V2rayN_Free", "https://t.me/s/free4allVPN", "https://t.me/s/configV2rayForFree",
    "https://t.me/s/FreeV2rays", "https://t.me/s/DigiV2ray", "https://t.me/s/v2rayNG_VPN",
    "https://t.me/s/freev2rayssr", "https://t.me/s/v2rayn_server", "https://t.me/s/iranvpnet",
    "https://t.me/s/vmess_iran", "https://t.me/s/configV2rayNG", "https://t.me/s/vpn_proxy_custom",
    "https://t.me/s/vpnmasi", "https://t.me/s/ViPVpn_v2ray", "https://t.me/s/vip_vpn_2022",
    "https://t.me/s/FOX_VPN66", "https://t.me/s/YtTe3la", "https://t.me/s/ultrasurf_12",
    "https://t.me/s/frev2rayng", "https://t.me/s/FreakConfig", "https://t.me/s/Awlix_ir",
    "https://t.me/s/arv2ray", "https://t.me/s/flyv2ray", "https://t.me/s/free_v2rayyy",
    "https://t.me/s/ip_cf", "https://t.me/s/lightning6", "https://t.me/s/mehrosaboran",
    "https://t.me/s/oneclickvpnkeys", "https://t.me/s/outline_vpn", "https://t.me/s/outlinev2rayng",
    "https://t.me/s/outlinevpnofficial", "https://t.me/s/v2rayngvpn", "https://t.me/s/V2raNG_DA",
    "https://t.me/s/V2rayNg_madam", "https://t.me/s/v2boxxv2rayng", "https://t.me/s/configshub2",
    "https://t.me/s/v2ray_configs_pool", "https://t.me/s/hope_net", "https://t.me/s/everydayvpn",
    "https://t.me/s/v2nodes", "https://t.me/s/shadowproxy66", "https://t.me/s/free_nettm"
]

SEND_TO_TELEGRAM = os.getenv('SEND_TO_TELEGRAM', 'false').lower() == 'true'
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
TELEGRAM_CHANNEL_ID = os.getenv('TELEGRAM_CHANNEL_ID')

def full_unquote(s: str) -> str:
    if '%' not in s: return s
    prev_s = ""
    while s != prev_s:
        prev_s = s
        s = urllib.parse.unquote(s)
    return s

def clean_previous_configs(configs: List[str]) -> List[str]:
    cleaned_configs = []
    for config in configs:
        try:
            if '#' in config:
                base_uri, tag = config.split('#', 1)
                decoded_tag = full_unquote(tag)
                cleaned_tag = re.sub(r'::[A-Z]{2}$', '', decoded_tag).strip()
                cleaned_configs.append(f"{base_uri}#{cleaned_tag}" if cleaned_tag else base_uri)
            else:
                cleaned_configs.append(config)
        except:
            cleaned_configs.append(config)
    return cleaned_configs

def scrape_configs_from_url(url: str) -> List[str]:
    configs = []
    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        channel_name = "@" + url.split("/s/")[1]
        new_tag = f">>{channel_name}"
        soup = BeautifulSoup(response.content, 'html.parser')
        all_text_content = "\n".join(tag.get_text('\n') for tag in soup.find_all(['div', 'code', 'blockquote', 'pre']))
        pattern = r'((?:vmess|vless|ss|hy2|trojan|hysteria2)://[^\s<>"\'`]+)'
        found_configs = re.findall(pattern, all_text_content)
        for config in found_configs:
            if config.startswith("vmess://"):
                try:
                    base_part = config.split('#', 1)[0].replace("vmess://", "")
                    base_part += '=' * (-len(base_part) % 4)
                    decoded_bytes = base64.b64decode(base_part)
                    vmess_data = json.loads(decoded_bytes.decode("utf-8", errors='ignore'))
                    vmess_data["ps"] = new_tag
                    updated_b64 = base64.b64encode(json.dumps(vmess_data, separators=(',', ':')).encode('utf-8')).decode('utf-8').rstrip('=')
                    configs.append("vmess://" + updated_b64)
                except: continue
            else:
                base_uri = config.split('#', 1)[0]
                configs.append(f"{base_uri}#{new_tag}")
        return configs
    except: return []

def run_sub_checker(input_configs: List[str]) -> List[str]:
    if not SUB_CHECKER_DIR.is_dir(): return []
    normal_txt_path = SUB_CHECKER_DIR / "normal.txt"
    final_txt_path = SUB_CHECKER_DIR / "final.txt"
    cl_py_path = SUB_CHECKER_DIR / "cl.py"
    normal_txt_path.write_text("\n".join(input_configs), encoding="utf-8")
    try:
        subprocess.run(["python", cl_py_path.name], cwd=SUB_CHECKER_DIR, capture_output=True, text=True, timeout=7200)
        if final_txt_path.exists():
            return [line.strip() for line in final_txt_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except: pass
    return []

def process_and_save_results(checked_configs: List[str]) -> Dict[str, int]:
    if not checked_configs: return {}

    loc_dir = ROOT_DIR / "loc"
    mix_dir = ROOT_DIR / "mix"

    if loc_dir.is_dir(): shutil.rmtree(loc_dir)
    loc_dir.mkdir(exist_ok=True)
    mix_dir.mkdir(exist_ok=True)

    configs_by_protocol = {"vless": [], "vmess": [], "ss": [], "trojan": [], "hy2": []}
    configs_by_location = {}

    for config in checked_configs:
        if config.startswith(("hysteria2://", "hy2://")): configs_by_protocol["hy2"].append(config)
        elif config.startswith("vless://"): configs_by_protocol["vless"].append(config)
        elif config.startswith("vmess://"): configs_by_protocol["vmess"].append(config)
        elif config.startswith("ss://"): configs_by_protocol["ss"].append(config)
        elif config.startswith("trojan://"): configs_by_protocol["trojan"].append(config)

        try:
            match = re.search(r'::([A-Za-z]{2})$', urllib.parse.unquote(config))
            loc_code = match.group(1).upper() if match else "XX"
        except: loc_code = "XX"
        
        if loc_code not in configs_by_location: configs_by_location[loc_code] = []
        configs_by_location[loc_code].append(config)

    for proto, configs in configs_by_protocol.items():
        if configs:
            (ROOT_DIR / f"{proto}.html").write_text("\n".join(configs), encoding="utf-8")

    (mix_dir / "sub.html").write_text("\n".join(checked_configs), encoding="utf-8")

    for loc_code, configs in configs_by_location.items():
        flag = "❓"
        try:
            country = pycountry.countries.get(alpha_2=loc_code)
            if country: flag = getattr(country, 'flag', "❓")
        except: pass
        (loc_dir / f"{loc_code} {flag}.txt").write_text("\n".join(configs), encoding="utf-8")

    return {proto: len(configs) for proto, configs in configs_by_protocol.items()}

def main():
    all_raw_configs = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(scrape_configs_from_url, TELEGRAM_URLS)
        for res in results: all_raw_configs.extend(res)
    unique_new = sorted(list(set(all_raw_configs)))

    previous = []
    prev_file = ROOT_DIR / "mix" / "sub.html"
    if prev_file.is_file():
        try:
            lines = prev_file.read_text(encoding="utf-8").splitlines()
            previous = clean_previous_configs([l.strip() for l in lines if '://' in l])
        except: pass

    combined = sorted(list(set(unique_new + previous)))
    if not combined: return

    checked = run_sub_checker(combined)
    protocol_counts = process_and_save_results(checked)

    if SEND_TO_TELEGRAM and TELEGRAM_BOT_TOKEN and TELEGRAM_CHANNEL_ID:
        try:
            bot = telegram_sender.init_bot(TELEGRAM_BOT_TOKEN)
            if bot and protocol_counts:
                telegram_sender.send_summary_message(bot, TELEGRAM_CHANNEL_ID, protocol_counts)
                grouped = telegram_sender.regroup_configs_by_source(checked)
                telegram_sender.send_all_grouped_configs(bot, TELEGRAM_CHANNEL_ID, grouped)
        except: pass

if __name__ == "__main__":
    main()
