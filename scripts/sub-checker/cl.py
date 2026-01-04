import socket
import re
import base64
import json
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor

def extract_host_port(config):
    try:
        if config.startswith("vmess://"):
            # دیکود کردن vmess
            b64_data = config.split("://")[1]
            # اصلاح padding بیس ۶۴
            missing_padding = len(b64_data) % 4
            if missing_padding:
                b64_data += '=' * (4 - missing_padding)
            decoded = base64.b64decode(b64_data).decode('utf-8')
            data = json.loads(decoded)
            return data.get('add'), int(data.get('port'))
        
        else:
            # برای vless, trojan, ss, hy2
            parsed = urlparse(config)
            host = parsed.hostname
            port = parsed.port
            if not port:
                # پورت‌های پیش‌فرض اگر در لینک نباشند
                if config.startswith("ss://"): port = 443
                else: port = 443
            return host, int(port)
    except:
        return None, None

def check_connection(config):
    host, port = extract_host_port(config)
    if not host or not port:
        return None

    try:
        # اضافه کردن مدیریت خطای یونیکد و طول کاراکتر
        with socket.create_connection((host, port), timeout=3):
            return config
    except (socket.timeout, ConnectionRefusedError, OSError, UnicodeError):
        # اگر آدرس سرور خراب بود یا پورت بسته بود، اینجا مدیریت می‌شود
        return None

def main():
    print("Checking configs...")
    try:
        with open("normal.txt", "r", encoding="utf-8") as f:
            configs = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("normal.txt not found!")
        return

    valid_configs = []
    # استفاده از ترد برای سرعت بالاتر (Multi-threading)
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(check_connection, configs))
        valid_configs = [c for c in results if c]

    with open("final.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(valid_configs))
    
    print(f"Done! Found {len(valid_configs)} valid configs.")

if __name__ == "__main__":
    main()
