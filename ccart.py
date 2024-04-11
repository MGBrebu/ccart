from datetime import datetime
from ciscoconfparse2 import CiscoConfParse

# ------------------------------------------------
# Cisco Configuration Auditing and Reporting Tool
# By Mario Brebu, Daniel Baldwin, and Mataz Al-Mashikhi
# In collaboration with greater Configuroo web application project
# ------------------------------------------------

# Datetime Init
dt = datetime.now()
ts = dt.strftime("%Y-%m-%d %H:%M:%S")

# === REPORT GENERATION ===
# Main report function generates report using header, footer, and all findings functions
def generateReport(user, file):
    print(f"Generating report for {file} at {ts}...    ", end="")

    # Get current user from configuroo.py
    curr_user = user
    # Create report file with timestamp and open for writing
    
    reportName = file.split("/")[-1].split(".")[0] + "_" + dt.strftime("%Y-%m-%d_%H-%M-%S") + ".txt"
    out = open('./output/' + reportName, 'w')
    # Parse the config file uploaded in configuroo.py
    config = CiscoConfParse(file)
    # Header
    generateReportHeader(curr_user, file, findHostname(config), findVersion(config), out)
    # Findings
    findInterfaces(config, out)
    findShutdownInterfaces(config, out)
    findPassword(config, out)
    # Footer
    generateReportFooter(out)

    print(f"Report generated!")

# Top of report includes datetime, current user*, and current config file
# * Placeholder for future implementation
def generateReportHeader(curr_user, file, hostname, version, out):
    out.write("=== BEGIN REPORT ===\n")
    out.write("Date/Time Generated: " + ts + "\n")
    out.write("Current User: " + curr_user + "\n")
    out.write("Configuration File: " + file + "\n\n")
    out.write("# DEVICE INFO\n")
    out.write("Hostname: " + hostname + "\n")
    out.write("Version: " + version + "\n\n")
    out.write("# FINDINGS\n")

# Bottom of report includes security score
def generateReportFooter(out):
    out.write("\n# SCORE")
    out.write("\nSecurity Score: NaN\n")
    out.write("\n=== END REPORT ===")
    out.close()
# =========================

# === FINDING DEVICE INFO ===
# Finding version and hostname for report header
def findVersion(config):
    try:
        version = config.find_objects(['version'])[0]
        return str(" ".join(version.text.split()[1:]))
    except IndexError:
        return "Unable to find version, IndexError\n" + str(IndexError)

def findHostname(config):
    try:
        hostname = config.find_objects(['hostname'])[0]
        return str(" ".join(hostname.text.split()[1:]))
    except IndexError:
        return "Unable to find hostname, IndexError\n" + str(IndexError)
# =========================

# === SECURITY CHECKS ===
# Finding interfaces
def findInterfaces(config, out):
    try:
        for intfaces in config.find_parent_objects(['interface']):
            intf = " ".join(intfaces.split()[1:])
            out.write(f"Interfaces: {intf}\n")
    except IndexError:
        out.write("Unable to find interfaces, IndexError\n" + str(IndexError))

# Finding shutdown interfaces
def findShutdownInterfaces(config, out):
    try:
        for intface_sh in config.find_parent_objects(['interface', 'shutdown']):
            intf_sh = " ".join(intface_sh.split()[1:])
            out.write(f"Shutdown Interfaces: {intf_sh}\n")
    except IndexError:
        out.write("Unable to find shutdown interfaces, IndexError\n" + str(IndexError))

# Finding if there is a password set
def findPassword(config, out):
    try:
        for password in config.find_objects(r"password"):
            if password.text.startswith("password"):
                out.write(f"Password: {password}\n")
                print(password)
    except IndexError:
        out.write("Unable to find password, IndexError\n" + str(IndexError))
# =========================

# =========================
# Main function
generateReport("ccart", "./configs/Default_startup-config.txt")
generateReport("ccart", "./configs/Passwords_startup-config.txt")