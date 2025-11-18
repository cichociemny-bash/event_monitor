import psutil
import time
from scapy.all import sniff, IP

def wait_for_process(process_name):
    while True:
        try:
            # Sprawdzenie, czy istnieje proces o podanej nazwie
            process = next(p for p in psutil.process_iter(['pid', 'name']) if p.info['name'] == process_name)
            print(f"[*] Found process: {process_name} (PID: {process.info['pid']})")
            return process
        except StopIteration:
            print(f"[*] Process {process_name} not found. Waiting...")
            time.sleep(5)  # Czekaj 5 sekund przed ponownym sprawdzeniem

def packet_handler(packet, connection):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = connection.laddr.port
        dst_port = connection.raddr.port

        if packet.haslayer("TCP"):
            protocol = "TCP"
        elif packet.haslayer("UDP"):
            protocol = "UDP"
        else:
            protocol = "Unknown"

        print(f"[*] Detected {protocol} packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}")

def monitor_process(process_name):
    process = wait_for_process(process_name)

    print(f"[*] Monitoring process: {process_name} (PID: {process.info['pid']})")

    while True:
        try:
            # Aktualizowanie informacji o procesie
            process_info = process.as_dict(attrs=['pid', 'name', 'cpu_percent', 'memory_percent'])
            print(f"[*] Process info: {process_info}")

            # Sprawdzanie wykonanych poleceń
            cmd_history = process.cmdline()
            print(f"[*] Executed commands: {cmd_history}")

            # Analiza ruchu sieciowego
            connections = process.connections()
            for conn in connections:
                sniff(filter=f"host {conn.raddr.ip}", prn=lambda pkt: packet_handler(pkt, conn), store=0)

            # Odczekaj chwilę przed ponownym sprawdzeniem
            time.sleep(1)
            process = psutil.Process(process.pid)  # Odśwież informacje o procesie

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            print("[!] Process terminated. Waiting for the process to restart.")
            process = wait_for_process(process_name)

        except KeyboardInterrupt:
            print("[*] Monitoring stopped by user.")
            break

if __name__ == "__main__":
    process_name = input("Podaj nazwę procesu do monitorowania: ")
    monitor_process(process_name)
