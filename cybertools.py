#!/usr/bin/env python3
# CyberTools - utilitarios de rede e seguranca para Termux
# Use somente em sistemas, dominios e redes que voce possui ou tem permissao para testar.

import os
import re
import ssl
import json
import socket
import hashlib
import ipaddress
import urllib.request
import urllib.parse
import urllib.error
import subprocess
from datetime import datetime
from html.parser import HTMLParser

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"

def clear():
    os.system("clear")

def title():
    clear()
    print(CYAN + BOLD + r"""
   _____      __              ______           __
  / ___/_  __/ /_  ___  _____/ ____/___  ____/ /_____
  \__ \| |/_/ __ \/ _ \/ ___/ /   / __ \/ __  / ___/
 ___/ />  </ /_/ /  __/ /  / /___/ /_/ / /_/ (__  )
/____/_/|_/_.___/\___/_/   \____/\____/\__,_/____/
""" + RESET)
    print(MAGENTA + "             TERMUX SECURITY TOOLKIT" + RESET)
    print("-" * 55)

def pause():
    input("\nEnter para voltar ao menu...")

def ask_target():
    return input("Dominio ou IP: ").strip()

def valid_host(value):
    value = value.strip()
    if not value or any(c in value for c in " /\\@"):
        raise ValueError("Informe somente um dominio ou IP, sem caminho ou usuario.")
    return value

def fetch(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": "CyberTools/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.headers, r.read(500000)

def dns_lookup():
    host = valid_host(ask_target())
    print(f"\nDNS de {host}")
    try:
        for item in sorted(set(x[4][0] for x in socket.getaddrinfo(host, None))):
            print(GREEN + " A/AAAA: " + RESET + item)
    except Exception as e:
        print(RED + f"Falha: {e}" + RESET)

def reverse_dns():
    ip = input("Endereco IP: ").strip()
    try:
        print(socket.gethostbyaddr(str(ipaddress.ip_address(ip))))
    except Exception as e:
        print(RED + f"Nao foi possivel resolver: {e}" + RESET)

def ip_info():
    value = input("Endereco IP: ").strip()
    try:
        ip = ipaddress.ip_address(value)
        print("Versao:", ip.version)
        print("Privado:", ip.is_private, "| Publico:", ip.is_global)
        print("Loopback:", ip.is_loopback, "| Reservado:", ip.is_reserved)
        print("Multicast:", ip.is_multicast)
        if ip.is_global:
            try:
                _, _, data = fetch("http://ip-api.com/json/" + urllib.parse.quote(str(ip)) + "?fields=status,message,country,regionName,city,isp,org,as,query")
                print(json.dumps(json.loads(data), indent=2, ensure_ascii=False))
            except Exception as e:
                print("Geolocalizacao indisponivel:", e)
    except ValueError:
        print(RED + "IP invalido." + RESET)

def whois_lookup():
    host = valid_host(ask_target())
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        print("Dominio invalido."); return
    try:
        p = subprocess.run(["whois", host], capture_output=True, text=True, timeout=15)
        print((p.stdout or p.stderr)[:12000] or "Sem resultado. Instale whois: pkg install whois")
    except FileNotFoundError:
        print("Comando whois ausente. Instale com: pkg install whois")
    except Exception as e:
        print("Erro:", e)

def http_headers():
    host = valid_host(ask_target())
    url = host if host.startswith(("http://", "https://")) else "https://" + host
    try:
        status, headers, _ = fetch(url)
        print("HTTP:", status)
        for k, v in headers.items():
            print(f"{k}: {v}")
    except Exception as e:
        print("HTTPS falhou:", e)
        try:
            status, headers, _ = fetch("http://" + host)
            print("HTTP:", status)
            for k, v in headers.items(): print(f"{k}: {v}")
        except Exception as e2:
            print("Falha:", e2)

def security_headers():
    host = valid_host(ask_target())
    url = host if host.startswith(("http://", "https://")) else "https://" + host
    wanted = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-content-type-options": "X-Content-Type-Options",
        "x-frame-options": "X-Frame-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }
    try:
        _, headers, _ = fetch(url)
        low = {k.lower(): v for k, v in headers.items()}
        for key, label in wanted.items():
            if key in low:
                print(GREEN + "[OK] " + RESET + label + ": " + low[key])
            else:
                print(YELLOW + "[--] " + RESET + label + ": nao encontrado")
    except Exception as e:
        print("Falha:", e)

def tls_check():
    host = valid_host(ask_target()).replace("https://", "").split("/")[0].split(":")[0]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                print("TLS:", s.version())
                print("Cifra:", s.cipher())
                print("Emitido para:", cert.get("subject"))
                print("Emissor:", cert.get("issuer"))
                print("Valido ate:", cert.get("notAfter"))
    except Exception as e:
        print("Falha TLS:", e)

def http_status():
    host = valid_host(ask_target())
    url = host if host.startswith(("http://", "https://")) else "https://" + host
    try:
        status, headers, _ = fetch(url)
        print("Status HTTP:", status)
        print("Servidor:", headers.get("Server", "nao informado"))
        print("Tipo:", headers.get("Content-Type", "nao informado"))
    except urllib.error.HTTPError as e:
        print("Status HTTP:", e.code, e.reason)
    except Exception as e:
        print("Falha:", e)

def robots_sitemap():
    host = valid_host(ask_target())
    base = host if host.startswith(("http://", "https://")) else "https://" + host
    base = base.rstrip("/")
    for path in ("/robots.txt", "/sitemap.xml"):
        print(f"\n--- {base + path} ---")
        try:
            _, _, data = fetch(base + path)
            print(data.decode("utf-8", "replace")[:7000])
        except Exception as e:
            print("Indisponivel:", e)

def tech_detect():
    host = valid_host(ask_target())
    url = host if host.startswith(("http://", "https://")) else "https://" + host
    try:
        _, headers, body = fetch(url)
        text = body[:150000].decode("utf-8", "ignore").lower()
        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        print("Server:", server or "nao identificado")
        print("X-Powered-By:", powered or "nao identificado")
        clues = {
            "WordPress": "wp-content" in text or "wp-includes" in text,
            "React": "react" in text,
            "Vue": "vue" in text,
            "Next.js": "next" in text,
            "Drupal": "drupal" in text,
            "Joomla": "joomla" in text,
        }
        for name, found in clues.items():
            if found: print(GREEN + "Possivel tecnologia: " + name + RESET)
    except Exception as e:
        print("Falha:", e)

def ping_host():
    host = valid_host(ask_target())
    try:
        flag = "-c"
        p = subprocess.run(["ping", flag, "4", host], text=True, capture_output=True, timeout=12)
        print(p.stdout or p.stderr)
    except Exception as e:
        print("Ping indisponivel:", e)

def traceroute():
    host = valid_host(ask_target())
    for cmd in (["traceroute", "-m", "12", host], ["tracepath", host]):
        try:
            p = subprocess.run(cmd, text=True, capture_output=True, timeout=25)
            print(p.stdout or p.stderr); return
        except FileNotFoundError:
            continue
        except Exception as e:
            print("Erro:", e); return
    print("Instale com: pkg install traceroute")

def port_check():
    print(YELLOW + "Use somente em host proprio ou com autorizacao." + RESET)
    host = valid_host(ask_target())
    confirm = input(f"Confirmar verificacao basica de portas em {host}? (s/N): ").lower()
    if confirm != "s": return
    ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 5432, 8080, 8443]
    try:
        ip = socket.gethostbyname(host)
        print("IP:", ip)
        for port in ports:
            s = socket.socket()
            s.settimeout(0.7)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0: print(GREEN + f"[ABERTA] {port}" + RESET)
    except Exception as e:
        print("Falha:", e)

def hash_text():
    value = input("Texto para gerar hash: ").encode()
    print("MD5:    ", hashlib.md5(value).hexdigest())
    print("SHA1:   ", hashlib.sha1(value).hexdigest())
    print("SHA256: ", hashlib.sha256(value).hexdigest())
    print("SHA512: ", hashlib.sha512(value).hexdigest())

def hash_file():
    path = input("Caminho do arquivo: ").strip()
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""): h.update(chunk)
        print("SHA256:", h.hexdigest())
    except Exception as e:
        print("Falha:", e)

def file_info():
    path = input("Caminho do arquivo: ").strip()
    try:
        with open(path, "rb") as f: head = f.read(32)
        signatures = {
            b"\x89PNG\r\n\x1a\n": "PNG", b"\xff\xd8\xff": "JPEG",
            b"GIF87a": "GIF", b"GIF89a": "GIF", b"%PDF": "PDF",
            b"PK\x03\x04": "ZIP/DOCX/XLSX/APK", b"\x7fELF": "Executavel ELF",
        }
        kind = next((v for k, v in signatures.items() if head.startswith(k)), "Tipo desconhecido")
        print("Tipo:", kind, "| Tamanho:", os.path.getsize(path), "bytes")
    except Exception as e:
        print("Falha:", e)

def ipv4_calc():
    value = input("Rede (ex.: 192.168.1.0/24): ").strip()
    try:
        n = ipaddress.ip_network(value, strict=False)
        print("Rede:", n, "\nMascara:", n.netmask, "\nBroadcast:", n.broadcast_address)
        print("Total de enderecos:", n.num_addresses)
        if n.num_addresses <= 1024:
            print("Hosts utilizaveis:", ", ".join(str(x) for x in n.hosts()))
    except Exception as e:
        print("Rede invalida:", e)

def url_analyze():
    raw = input("URL: ").strip()
    url = raw if "://" in raw else "https://" + raw
    try:
        p = urllib.parse.urlparse(url)
        print("Esquema:", p.scheme)
        print("Dominio:", p.hostname)
        print("Porta:", p.port or ("443" if p.scheme == "https" else "80"))
        print("Caminho:", p.path or "/")
        print("Parametros:", p.query or "nenhum")
        print("Usuario/senha na URL:", "SIM - evite compartilhar" if p.username or p.password else "nao")
        print("HTTPS:", "sim" if p.scheme == "https" else "nao")
    except Exception as e:
        print("URL invalida:", e)

def email_format():
    value = input("Email para validar formato: ").strip()
    ok = bool(re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value))
    print(GREEN + "Formato parece valido." + RESET if ok else RED + "Formato invalido." + RESET)
    print("Isso nao confirma que a caixa postal existe.")

def main():
    actions = {
        "1": ("DNS Lookup", dns_lookup),
        "2": ("Reverse DNS", reverse_dns),
        "3": ("IP Info / Geolocalizacao aproximada", ip_info),
        "4": ("WHOIS", whois_lookup),
        "5": ("HTTP Headers", http_headers),
        "6": ("Security Headers", security_headers),
        "7": ("TLS / SSL Checker", tls_check),
        "8": ("HTTP Status Checker", http_status),
        "9": ("Robots.txt / Sitemap Viewer", robots_sitemap),
        "10": ("Technology Detector basico", tech_detect),
        "11": ("Ping", ping_host),
        "12": ("Traceroute", traceroute),
        "13": ("Port Check basico (autorizado)", port_check),
        "14": ("Hash Generator", hash_text),
        "15": ("File SHA-256", hash_file),
        "16": ("File Type Detector", file_info),
        "17": ("IPv4 Subnet Calculator", ipv4_calc),
        "18": ("URL Analyzer", url_analyze),
        "19": ("Email Format Checker", email_format),
    }
    while True:
        title()
        for key, (label, _) in actions.items():
            print(f"{CYAN}{key:>2}.{RESET} {label}")
        print(f"{RED} 0.{RESET} Sair")
        choice = input("\nCyberTools > ").strip()
        if choice == "0":
            print("Encerrando CyberTools."); break
        action = actions.get(choice)
        if not action:
            input("Opcao invalida. Enter para continuar...")
            continue
        clear()
        print(CYAN + BOLD + f"--- {action[0]} ---" + RESET + "\n")
        try: action[1]()
        except KeyboardInterrupt: print("\nCancelado.")
        except Exception as e: print("Erro:", e)
        pause()

if __name__ == "__main__":
    main()
