import nmap


def scan():
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.0.1', arguments='-sS')
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]['state'] == 'open':
                    print("Port: %s/%s" % (port, proto))

# Import
#nm = nmap.PortScanner()

# Scan
#nm.scan(hosts='192.168.0.0/24', arguments='-sn') scans network
#nm.scan(hosts='192.168.0.1', arguments='-sS') # scans host
#nm.scan(hosts='192.168.0.66', arguments='-st')

# Print
# print(nm.scaninfo())
# print(nm.all_hosts())

# prints all hosts
# for host in nm.all_hosts():
#     if nm[host].state() == "up":
#         print("Host: %s" % host)

# prints all open ports
# for host in nm.all_hosts():
#     for proto in nm[host].all_protocols():
#         lport = nm[host][proto].keys()
#         for port in lport:
#             if nm[host][proto][port]['state'] == 'open':
#                 print("Port: %s/%s" % (port, proto))

# for host in nm.all_hosts():
#     for proto in nm[host].all_protocols():
#         lport = nm[host][proto].keys()
#         for port in lport:
#             if nm[host][proto][port]['state'] == 'open':
#                 print(f'Open Port: {port}/{proto}')
