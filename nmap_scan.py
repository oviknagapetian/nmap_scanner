import nmap

def scan_network(target):
    nm = nmap.PortScanner()
    print(f"Сканирование целевого адреса: {target}")
    try:
        nm.scan(hosts=target, arguments='-sS')  # -sS для сканирования SYN
    except nmap.PortScannerError as e:
        print(f"Ошибка при сканировании: {e}")
        return
    
    for host in nm.all_hosts():
        print(f'Host: {host} ({nm[host].hostname()})')
        print(f'State: {nm[host].state()}')
        for proto in nm[host].all_protocols():
            print(f'Protocol: {proto}')
            lport = nm[host][proto].keys()
            for port in lport:
                print(f'Port: {port}\tState: {nm[host][proto][port]["state"]}')
        print('-' * 60)

if __name__ == "__main__":
    target = input("Введите целевой IP-адрес или диапазон IP-адресов (например, 192.168.1.0/24): ")
    scan_network(target)
