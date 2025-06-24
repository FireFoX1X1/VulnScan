import subprocess
import xml.etree.ElementTree as ET

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def card(title, lines):
    border = f"{Colors.OKCYAN}{'─' * (len(title) + 4)}{Colors.ENDC}"
    print(f"\n{Colors.OKCYAN}┌{border}┐{Colors.ENDC}")
    print(f"{Colors.OKCYAN}│  {Colors.BOLD}{title}{Colors.ENDC}{Colors.OKCYAN}  │{Colors.ENDC}")
    print(f"{Colors.OKCYAN}├{border}┤{Colors.ENDC}")
    for line in lines:
        print(f"{Colors.OKCYAN}│{Colors.ENDC} {line}")
    print(f"{Colors.OKCYAN}└{border}┘{Colors.ENDC}")

def scan_host_with_nmap(ip, ports):
    print(f"{Colors.OKBLUE}[+] Escaneando {ip} nas portas: {ports}{Colors.ENDC}")
    cmd = ["nmap", "-sV", "-O", "-p", ports, "--open", "-oX", "-", ip]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def scan_nmap_vuln_scripts(ip, ports):
    print(f"{Colors.OKBLUE}[+] Executando scripts de vulnerabilidade do Nmap em {ip} portas {ports}{Colors.ENDC}")
    cmd = ["nmap", "-p", ports, "--script", "vuln", "-oX", "-", ip]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def parse_host_info(xml_output):
    root = ET.fromstring(xml_output)
    host_info = {
        "ip": "N/D",
        "hostname": "N/D",
        "os": "N/D",
        "uptime": "N/D",
        "scan_time": "N/D"
    }

    address = root.find(".//address")
    if address is not None:
        host_info["ip"] = address.attrib.get("addr", "N/D")

    hostname = root.find(".//hostnames/hostname")
    if hostname is not None:
        host_info["hostname"] = hostname.attrib.get("name", "N/D")

    os = root.find(".//os/osmatch")
    if os is not None:
        host_info["os"] = os.attrib.get("name", "N/D")

    uptime = root.find(".//uptime")
    if uptime is not None:
        host_info["uptime"] = uptime.attrib.get("lastboot", "N/D")

    finished = root.find(".//runstats/finished")
    if finished is not None:
        host_info["scan_time"] = finished.attrib.get("timestr", "N/D")

    return host_info

def parse_nmap_xml_services(xml_output):
    services = []
    root = ET.fromstring(xml_output)
    for port in root.findall(".//port"):
        service = port.find("service")
        if service is not None:
            product = service.attrib.get("product", "")
            version = service.attrib.get("version", "")
            name = service.attrib.get("name", "")
            if product:
                full_name = f"{product} {version}".strip()
            else:
                full_name = f"{name} {version}".strip()
            services.append(full_name)
    return list(set(services))

def parse_nmap_vulns(xml_output):
    vulns = []
    root = ET.fromstring(xml_output)
    for elem in root.findall(".//script[@id='vulners']"):
        output = elem.attrib.get("output", "")
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if line:
                vulns.append(line)
    for script in root.findall(".//script"):
        if 'vuln' in script.attrib.get('id', '') and script.attrib.get('output'):
            vulns.append(script.attrib['output'].strip())
    return vulns
