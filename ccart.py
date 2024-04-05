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
# Datetime Init
dt = datetime.now()
ts = dt.strftime("%Y-%m-%d %H:%M:%S")
# Init output report file
reportName = "report_" + dt.strftime("%Y-%m-%d_%H-%M-%S") + ".txt"
out = open("./output/" + reportName, "w")

# === REPORT GENERATION ===
# Top of report includes datetime, current user*, and current config file
# * Placeholder for future implementation
def generateReportHeader(hostname, version):
    out.write("=== BEGIN REPORT ===\n")
    out.write("Date/Time Generated: " + ts + "\n")
    out.write("Current User: " + CURR_USER + "\n")
    out.write("Configuration File: " + CFG_FILE + "\n\n")
    out.write("# DEVICE INFO\n")
    out.write("Hostname: " + hostname + "\n")
    out.write("Version: " + version + "\n\n")
    out.write("# FINDINGS\n")

# Bottom of report includes security score
def generateReportFooter():
    out.write("\n# SCORE")
    out.write("\nSecurity Score: NaN\n")
    out.write("\n=== END REPORT ===")
    out.close()
# =========================

# === FINDING DEVICE INFO ===
# Finding version and hostname for report header
def findVersion():
    version = config.find_objects(['version'])[0]
    return str(" ".join(version.text.split()[1:]))

def findHostname():
    hostname = config.find_objects(['hostname'])[0]
    return str(" ".join(hostname.text.split()[1:]))
# =========================

# === SECURITY CHECKS ===
# Finding interfaces
def findInterfaces():
    for intfaces in config.find_parent_objects(['interface']):
        intf = " ".join(intfaces.split()[1:])
        out.write(f"Interfaces: {intf}\n")

# Finding shutdown interfaces
def findShutdownInterfaces(): 
    for intface_sh in config.find_parent_objects(['interface', 'shutdown']):
        intf_sh = " ".join(intface_sh.split()[1:])
        out.write(f"Shutdown Interfaces: {intf_sh}\n")

# Finding if there is a password set
def findPassword():
    for password in config.find_objects(r"password"):
        if password.text.startswith("password"):
            out.write(f"Password: {password}\n")
            print(password)
# =========================

# === MAIN ===
# Generates reporter header with hostname and version
generateReportHeader(findHostname(), findVersion())

# Generates findings
findVersion()
findHostname()
findInterfaces()
findShutdownInterfaces()
findPassword()

# Generates report footer
generateReportFooter()