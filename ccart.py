import os
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
    print(f"Generating report for {file.split('/')[-1]} at {ts}...    ")
    # Get current user
    curr_user = user
    # Create report file with timestamp and open for writing
    reportName = file.split("/")[-1].split(".")[0] + "_" + dt.strftime("%Y-%m-%d_%H-%M-%S") + ".txt"
    try: 
        out = open('./output/' + reportName, 'w')
        # Parse the config file uploaded in configuroo.py
        config = CiscoConfParse(file)
        # Header
        generateReportHeader(curr_user, file, out)
        # Device Info
        version = findVersion(config)
        hostname = findHostname(config)
        intf = findInterfaces(config)
        sh_intf = findShutdownInterfaces(config)
        generateReportDeviceInfo(hostname, version, intf, sh_intf, out)
        # Audit
        generateReportAudit(config, out)
        # Footer
        generateReportFooter(out)
    except Exception as e:
        out.close()
        os.remove(f"./output/{reportName}")
        open('./output/' + "error_" + reportName, 'w').write(f"Error generating report:\n {e}")
        print(f"Error generating report:\n {e}")

    print(f"Report generated!")

# Generate report header
# Includes datetime, current user*, and current config file
# * Placeholder for future implementation
def generateReportHeader(curr_user, file, out):
    out.write("=== BEGIN REPORT ===\n")
    out.write("# REPORT INFO\n")
    out.write("Date/Time Generated: " + ts + "\n")
    out.write("Current User: " + curr_user + "\n")
    out.write("Configuration File: " + file + "\n")

# Generate device info
# Includes hostname, version, interfaces, and shutdown interfaces
def generateReportDeviceInfo(hostname, version, intf, sh_intf, out):
    out.write("\n# DEVICE INFO\n")
    out.write("Hostname: " + hostname + "\n")
    out.write("Version: " + version + "\n")
    out.write("Interfaces:\n")
    for i in intf:
        out.write("- " + " ".join(i.split()[1:]) + "\n")
    out.write("Shutdown Interfaces:\n")
    for i in sh_intf:
        out.write("- " + " ".join(i.split()[1:]) + "\n")

# Generate audit report
# Includes all audit findings
def generateReportAudit(config, out):
    out.write("\n# AUDIT\n")
    out.write("Audit: NaN\n")

# Generate report footer
# Includes security score and end of report
def generateReportFooter(out):
    out.write("\n# SCORE")
    out.write("\nSecurity Score: NaN\n")
    out.write("\n=== END REPORT ===")
    out.close()
# =========================

# === DEVICE INFO ===
# Finding version
def findVersion(config):
    try:
        version = config.find_objects(['version'])[0]
        return str(" ".join(version.text.split()[1:]))
    except IndexError:
        return "Unable to find version, IndexError\n" + str(IndexError)

# Finding hostname
def findHostname(config):
    try:
        hostname = config.find_objects(['hostname'])[0]
        return str(" ".join(hostname.text.split()[1:]))
    except IndexError:
        return "Unable to find hostname, IndexError\n" + str(IndexError)

# Finding interfaces
def findInterfaces(config):
    try:
        print("# Finding interfaces...")
        intfaces = config.find_parent_objects(['interface'])
        print("# Interfaces found!")
        return intfaces
    except IndexError:
        print("# X Unable to find interfaces, IndexError\n" + str(IndexError))
        return ["- Unable to find interfaces in this config file."]

# Finding shutdown interfaces
def findShutdownInterfaces(config):
    try:
        print("# Finding shutdown interfaces...")
        sh_intfaces = config.find_parent_objects(['interface', 'shutdown'])
        if sh_intfaces == []:
            raise Exception("Search returned empty list.")
        print("# Shutdown interfaces found!")
        return sh_intfaces
    except Exception as e:
        print("# X Unable to find shutdown interfaces\n" + str(e))
        return ["- Unable to find shutdown interfaces in this config file."]
# =========================

# === AUDIT ===
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
#generateReport("ccart", "./configs/Passwords_startup-config.txt")