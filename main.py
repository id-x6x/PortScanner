import socket
from datetime import datetime
from threading import Thread, Semaphore
from queue import Queue
from tqdm import tqdm

MAX_THREADS = 100
thread_semaphore = Semaphore(MAX_THREADS)

open_ports = []


def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "unknown"


def reverse_dns_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "No reverse DNS record"


def scan_port(target_ip, port, progress_bar):
    with thread_semaphore:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                service = get_service_name(port)
                open_ports.append((port, service))
        except Exception:
            pass
        finally:
            sock.close()
            progress_bar.update(1)


def worker(queue, target_ip, progress_bar):
    while not queue.empty():
        port = queue.get()
        scan_port(target_ip, port, progress_bar)
        queue.task_done()


def scan_ports_multithreaded(target, start_port, end_port):
    print(f"\nScanning target {target} from port {start_port} to {end_port}\n")

    try:
        target_ip = socket.gethostbyname(target)
        print(f"Target IP: {target_ip}\n")
    except socket.gaierror:
        return

    rDNS = reverse_dns_lookup(target_ip)
    print(f"Reverse DNS: {rDNS}\n")

    start_time = datetime.now()
    port_queue = Queue()

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    threads = []
    with tqdm(total=end_port - start_port + 1, desc="Scanning Ports", unit="port") as progress_bar:
        for _ in range(MAX_THREADS):
            t = Thread(target=worker, args=(port_queue, target_ip, progress_bar))
            t.daemon = True
            t.start()
            threads.append(t)

        port_queue.join()

    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\nScan completed in: {duration}\n")


    if open_ports:
        print(f"{'PORT':<10}{'STATE'}{' SERVICE':<15}")
        print("-" * 30)
        for port, service in sorted(open_ports):
            print(f"{port:<10}{'Open':<8}{service:<15}")
    else:
        print("No open ports found.\n")


def get_user_input():
    target = input("Enter target (domain or IP address): ").strip()

    while True:
        try:
            start_port = int(input("Enter start port (1-65535): ").strip())
            if 1 <= start_port <= 65535:
                break
            else:
                print("Please enter a port number between 1 and 65535.")
        except ValueError:
            print("Invalid input. Please enter a numeric value for the port.")

    while True:
        try:
            end_port = int(input("Enter end port (1-65535): ").strip())
            if 1 <= end_port <= 65535 and end_port >= start_port:
                break
            else:
                print(f"Please enter a port number between {start_port} and 65535.")
        except ValueError:
            print("Invalid input. Please enter a numeric value for the port.")

    return target, start_port, end_port


if __name__ == "__main__":
    print("=== Port Scanner ===\n")
    target, start_port, end_port = get_user_input()
    scan_ports_multithreaded(target, start_port, end_port)
