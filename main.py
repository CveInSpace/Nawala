import os
import sys
import json
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor

VERSION = "1.0.0"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def check_update():
    try:
        url = "https://raw.githubusercontent.com/CveInSpace/Nawala/main/version.txt"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as res:
            latest = res.read().decode().strip()
            if latest != VERSION:
                return f"\033[91m[!] New Update Available: {latest}\033[0m"
            return f"\033[92m[+] Version : {VERSION} (Latest)\033[0m"
    except:
        return f"\033[96m[+] Version : {VERSION}\033[0m"

def print_banner():
    clear_screen()
    banner = f"""
\033[96m ██████╗██╗   ██╗███████╗    ██╗███╗   ██╗    ███████╗██████╗  █████╗  ██████╗███████╗
██╔════╝██║   ██║██╔════╝    ██║████╗  ██║    ██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝
██║     ██║   ██║█████╗      ██║██╔██╗ ██║    ███████╗██████╔╝███████║██║     █████╗  
██║     ╚██╗ ██╔╝██╔══╝      ██║██║╚██╗██║    ╚════██║██╔═══╝ ██╔══██║██║     ██╔══╝  
╚██████╗ ╚████╔╝ ███████╗    ██║██║ ╚████║    ███████║██║     ██║  ██║╚██████╗███████╗
 ╚═════╝  ╚═══╝  ╚══════╝    ╚═╝╚═╝  ╚═══╝    ╚══════╝╚═╝     ╚═╝  ╚══╝ ╚═════╝╚══════╝
\033[0m"""
    print(banner)
    print("\033[96m" + "="*85)
    print(f"\033[93m[+] Author  : \033[0mKanezama")
    print(f"\033[93m[+] Site    : \033[0mcve-in.space")
    print(check_update())
    print("\033[96m" + "="*85)
    
    warning_text = f"""
\033[91m[!] WARNING: OFFICIAL TOOL FROM cve-in.space
\033[91m[!] STRICTLY PROHIBITED TO SELL OR REDISTRIBUTE THIS TOOL!
"""
    print(warning_text)
    print("\033[96m" + "="*85 + "\033[0m\n")

BLOCK_IPS = [
    '103.245.2.146', '103.245.2.147',
    '118.98.4.150', '118.98.4.172', '180.250.246.5', '36.86.63.182',
    '103.82.24.11', '112.215.89.10', '112.215.89.11',
    '0.0.0.0', '127.0.0.1'
]

def query_doh(domain, provider="google"):
    if provider == "google":
        url = f"https://dns.google/resolve?name={domain}&type=A"
    elif provider == "nawala_simulator":
        url = f"https://family.cloudflare-dns.com/dns-query?name={domain}&type=A"
        
    req = urllib.request.Request(
        url, 
        headers={'Accept': 'application/dns-json', 'User-Agent': 'Mozilla/5.0'}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode())
    except:
        return None

def check_domain(domain):
    domain = domain.strip().replace("http://", "").replace("https://", "").split("/")[0]
    if not domain:
        return None
        
    g_data = query_doh(domain, "google")
    if not g_data or g_data.get("Status") == 3:
        return "error_or_dead", domain
        
    real_ips = []
    if "Answer" in g_data:
        real_ips = [ans["data"] for ans in g_data["Answer"] if ans.get("type") == 1]
        
    if not real_ips:
        return "error_or_dead", domain

    nawala_data = query_doh(domain, "nawala_simulator")
    if nawala_data:
        if nawala_data.get("Status") == 3:
            return "blocked", domain
            
        if "Answer" in nawala_data:
            nawala_ips = [ans["data"] for ans in nawala_data["Answer"] if ans.get("type") == 1]
            if any(ip in BLOCK_IPS for ip in nawala_ips):
                return "blocked", domain

    try:
        local_ips = socket.gethostbyname_ex(domain)[2]
        if any(ip in BLOCK_IPS for ip in local_ips):
            return "blocked", domain
    except socket.gaierror:
        return "blocked", domain

    return "clean", domain

def main():
    print_banner()
    
    user_input = input(f"\033[92m[?] Input List / Domain : \033[0m").strip()
    
    domains = []
    is_single_domain = False

    if os.path.exists(user_input) and os.path.isfile(user_input):
        with open(user_input, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        if user_input:
            domains = [user_input]
            is_single_domain = True
        else:
            print(f"\033[91m[-] Empty input!\033[0m\n")
            return

    save_to_file = False
    output_file = "results.txt"
    
    if not is_single_domain:
        save_choice = input(f"\033[92m[?] Wanna save results? (y/n) : \033[0m").strip().lower()
        save_to_file = True if save_choice in ['y', 'yes'] else False
        if save_to_file:
            print(f"\033[93m[*] Output -> {output_file}\033[0m\n")
        
    print(f"\033[96m[*] Total: {len(domains)}")
    print(f"\033[96m[*] Progressing...\n\033[0m")
    print("\033[96m" + "="*85 + "\033[0m")

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_domain, domains)
        
        for result in results:
            if not result:
                continue
                
            status, domain = result
            
            if status == "clean":
                msg = f"\033[92m[+] {domain} -> Clean!\033[0m"
                print(msg)
                if save_to_file:
                    with open(output_file, 'a') as f_out:
                        f_out.write(f"[CLEAN] {domain}\n")
                        
            elif status == "blocked":
                msg = f"\033[91m[-] {domain} -> Blocked!\033[0m"
                print(msg)
                if save_to_file:
                    with open(output_file, 'a') as f_out:
                        f_out.write(f"[BLOCKED] {domain}\n")
            else:
                msg = f"\033[93m[!] {domain} -> Error / Dead\033[0m"
                print(msg)

    print(f"\n\033[96m" + "="*85)
    print(f"\033[92m[+] Done! visit cve-in.space\033[0m")
    print("\033[96m" + "="*85 + "\033[0m")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)