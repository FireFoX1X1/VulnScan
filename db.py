import sqlite3
import os

db_path = os.path.join("data", "scan_results.db")

def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY,
        ip TEXT,
        hostname TEXT,
        os TEXT,
        uptime TEXT,
        scan_time TEXT
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY,
        host_id INTEGER,
        name TEXT,
        FOREIGN KEY(host_id) REFERENCES hosts(id)
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY,
        host_id INTEGER,
        description TEXT,
        FOREIGN KEY(host_id) REFERENCES hosts(id)
    )''')
    conn.commit()
    conn.close()

def salvar_dados_no_banco(host_info, services, vulns):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO hosts (ip, hostname, os, uptime, scan_time) VALUES (?, ?, ?, ?, ?)",
                   (host_info['ip'], host_info['hostname'], host_info['os'], host_info['uptime'], host_info['scan_time']))
    host_id = cursor.lastrowid
    for s in services:
        cursor.execute("INSERT INTO services (host_id, name) VALUES (?, ?)", (host_id, s))
    for v in vulns:
        cursor.execute("INSERT INTO vulnerabilities (host_id, description) VALUES (?, ?)", (host_id, v))
    conn.commit()
    conn.close()

def exibir_todos_os_hosts():
    from main import card
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM hosts")
    hosts = cursor.fetchall()
    for host in hosts:
        host_id, ip, hostname, osname, uptime, scan_time = host
        cursor.execute("SELECT name FROM services WHERE host_id = ?", (host_id,))
        services = [s[0] for s in cursor.fetchall()]
        cursor.execute("SELECT description FROM vulnerabilities WHERE host_id = ?", (host_id,))
        vulns = [v[0] for v in cursor.fetchall()]
        card(f"HOST ID {host_id} - {ip}", [
            f"Hostname: {hostname}",
            f"Sistema Operacional: {osname}",
            f"Último Boot: {uptime}",
            f"Scan realizado em: {scan_time}",
            "Serviços:"] + [f"  - {s}" for s in services] + ["Vulnerabilidades:"] + [f"  - {v}" for v in vulns])
    conn.close()

def deletar_host_por_id(host_id):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vulnerabilities WHERE host_id = ?", (host_id,))
    cursor.execute("DELETE FROM services WHERE host_id = ?", (host_id,))
    cursor.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
    conn.commit()
    conn.close()

def atualizar_hostname_por_id(host_id, novo_hostname):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("UPDATE hosts SET hostname = ? WHERE id = ?", (novo_hostname, host_id))
    conn.commit()
    conn.close()

def top_3_hosts_com_mais_servicos():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT h.id, h.ip, h.hostname, COUNT(s.id) as total_servicos
        FROM hosts h
        JOIN services s ON h.id = s.host_id
        GROUP BY h.id
        ORDER BY total_servicos DESC
        LIMIT 3
    """)
    resultados = cursor.fetchall()
    conn.close()
    return resultados
