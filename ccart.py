# Cisco Confuguration Auditing and Reporting Tool
# By Mario Brebu, Daniel Baldwin, and Mataz Al-Mashikhi
# In collaboration with greater Configuroo web application project

from ciscoconfparse2 import CiscoConfParse

config = CiscoConfParse('./configs/Router0_running-config.txt')

out = open("./output/hostname.txt", "w")

# Findings and printing hostname
for hostname in config.find_parent_objects(['hostname']):
    host = " ".join(hostname.split()[1:])
    print(f"Hostname: {host}")
    out.write(f"Hostname: {host}\n")

out.write("\n")

# Finding interfaces
for intfaces in config.find_parent_objects(['interface']):
    intf = " ".join(intfaces.split()[1:])
    print(f"Interfaces: {intf}")
    out.write(f"Interfaces: {intf}\n")

out.write("\n")

# Finding shutdown interfaces
for intfacessh in config.find_parent_objects(['interface', 'shutdown']):
    intfsh = " ".join(intfacessh.split()[1:])
    print(f"Shutdown Interfaces: {intfsh}")
    out.write(f"Shutdown Interfaces: {intfsh}\n")
