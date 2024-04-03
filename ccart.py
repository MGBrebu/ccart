from datetime import datetime
from ciscoconfparse2 import CiscoConfParse

# ------------------------------------------------
# Cisco Confuguration Auditing and Reporting Tool
# By Mario Brebu, Daniel Baldwin, and Mataz Al-Mashikhi
# In collaboration with greater Configuroo web application project
# ------------------------------------------------

# Constants
# Connection points from webapp
CFG_FILE = './configs/Router0_running-config.txt'
CURR_USER = 'configuroo'
# Init CiscoConfParse with current config path
config = CiscoConfParse(CFG_FILE)
# Init file to output to
out = open("./output/output.txt", "w")
# Datetime Init
dt = datetime.now()
ts = dt.strftime("%Y-%m-%d %H:%M:%S")

# === REPORT GENERATION ===
def generateReportHeader():
    out.write("=== REPORT ===\n")
    out.write("Date/Time Generated: " + ts + "\n")
    out.write("Current User: " + CURR_USER + "\n")
    out.write("Configuration File: " + CFG_FILE + "\n\n")
    out.write("=== FINDINGS ===\n")

def generateReportFooter():
    out.write("=== END OF REPORT ===\n")
    out.write("\nSecurity Score: NaN\n")
    out.close()
# =========================

# === SECURITY CHECKS ===
# Findings hostname
def findHostname():
    for hostname in config.find_parent_objects(['hostname']):
        host = " ".join(hostname.split()[1:])
        print(f"Hostname: {host}")
        out.write(f"Hostname: {host}\n")

# Finding interfaces
def findInterfaces():
    for intfaces in config.find_parent_objects(['interface']):
        intf = " ".join(intfaces.split()[1:])
        print(f"Interfaces: {intf}")
        out.write(f"Interfaces: {intf}\n")

# Finding shutdown interfaces
def findShutdownInterfaces(): 
    for intface_sh in config.find_parent_objects(['interface', 'shutdown']):
        intf_sh = " ".join(intface_sh.split()[1:])
        print(f"Shutdown Interfaces: {intf_sh}")
        out.write(f"Shutdown Interfaces: {intf_sh}\n")

# Finding if there is a password set
def findPassword():
    for password in config.find_objects(r"password"):
        print(f"Password: {password.text}")
        out.write(f"Password: {password.text}\n")
# =========================

# === MAIN ===
generateReportHeader()

findHostname()
findInterfaces()
findShutdownInterfaces()
findPassword()

generateReportFooter()