import subprocess
import xml.etree.ElementTree as ET
from db import (
    init_db,
    salvar_dados_no_banco,
    exibir_todos_os_hosts,
    deletar_host_por_id,
    atualizar_hostname_por_id,
    top_3_hosts_com_mais_servicos
)

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
    status = root.find(".//status")
    if status is None or status.attrib.get("state") != "up":
        return None

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

def main():
    init_db()
    while True:
        print(f"\n{Colors.BOLD}{Colors.HEADER}╔══════════════════════════════════════════╗")
        print(f"║              MENU PRINCIPAL              ║")
        print(f"╚══════════════════════════════════════════╝{Colors.ENDC}")
        print("1. Realizar novo scan")
        print("2. Ver todos os resultados salvos")
        print("3. Deletar resultado por ID")
        print("4. Atualizar hostname de um host")
        print("5. Ver top 3 hosts com mais serviços")
        print("6. Sair")

        opcao = input("Escolha uma opção: ").strip()

        if opcao == "1":
            ip = input(f"{Colors.BOLD}Digite o IP do host para escanear: {Colors.ENDC}").strip()
            ports = input(f"{Colors.BOLD}Digite as portas para escanear (ex: 22,80 ou 1-1024): {Colors.ENDC}").strip()
            xml_services = scan_host_with_nmap(ip, ports)
            host_info = parse_host_info(xml_services)
            if host_info is None:
                print(f"{Colors.WARNING}⚠ Host parece estar offline. Nada será salvo.{Colors.ENDC}")
                continue
            services = parse_nmap_xml_services(xml_services)
            xml_vulns = scan_nmap_vuln_scripts(ip, ports)
            nmap_vulns = parse_nmap_vulns(xml_vulns)
            salvar_dados_no_banco(host_info, services, nmap_vulns)
            print(f"\n{Colors.OKGREEN}✔ Scan salvo com sucesso no banco de dados.{Colors.ENDC}")

        elif opcao == "2":
            exibir_todos_os_hosts()

        elif opcao == "3":
            try:
                host_id = int(input("Digite o ID do host a ser deletado: "))
                deletar_host_por_id(host_id)
                print(f"{Colors.OKGREEN}✔ Host com ID {host_id} deletado.{Colors.ENDC}")
            except ValueError:
                print(f"{Colors.FAIL}ID inválido.{Colors.ENDC}")

        elif opcao == "4":
            try:
                host_id = int(input("Digite o ID do host a ser atualizado: "))
                novo_hostname = input("Novo hostname: ").strip()
                atualizar_hostname_por_id(host_id, novo_hostname)
                print(f"{Colors.OKGREEN}✔ Hostname atualizado com sucesso!{Colors.ENDC}")
            except ValueError:
                print(f"{Colors.FAIL}ID inválido.{Colors.ENDC}")

        elif opcao == "5":
            top3 = top_3_hosts_com_mais_servicos()
            if top3:
                print(f"\n{Colors.BOLD}{Colors.OKCYAN}Top 3 hosts com mais serviços (mais expostos):{Colors.ENDC}")
                for id_, ip, hostname, total in top3:
                    print(f"  ID {id_} | IP: {ip} | Hostname: {hostname} | Serviços: {total}")
            else:
                print(f"{Colors.WARNING}Nenhum dado encontrado.{Colors.ENDC}")

        elif opcao == "6":
            print("Saindo...")
            break
        else:
            print(f"{Colors.FAIL}Opção inválida!{Colors.ENDC}")

if __name__ == "__main__":
    main()
