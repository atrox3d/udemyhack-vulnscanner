import portscanner

target_ip = input('[+] Enter target to scan for vulnerable oper ports: ')
port_number = int(input('[+] Enter amount of ports you want to scann (500 - first 500 open ports):'))
vul_file = input('[+] Enter path to the file with vulnerable softwares: ')
print('\n')

target = portscanner.PortScan(target_ip, port_number)

print("start scan...")
target.scan()
print("end scan...")

with open(vul_file) as file:
    count = 0
    for banner in target.banners:
        # print(f"check for banner: [{banner}]")
        file.seek(0)
        for line in file.readlines():
            # print(f"\t{{{line.strip()}}}")
            if line.strip() in banner:
                print(f"[!!] VULNERABLE BANNER '{banner}' on port {target.open_ports[count]}")
        count += 1
