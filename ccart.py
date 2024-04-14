import os
import sys
import json
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

# === REPORT GENERATION FUNCTIONALITY ===
# Main report function generates report using header, footer, and all findings functions
def generateReport(user, file):
    print(f"Generating report for {file.split('/')[-1]} at {ts}...    ")
    # Get current user
    curr_user = user
    # Create report file with timestamp and open for writing
    reportName = file.split("/")[-1].split(".")[0] + "_" + dt.strftime("%Y-%m-%d_%H-%M-%S") + ".txt"
    try: 
        # Initialize report file
        out = open('./output/' + reportName, 'w')

        # Import config file to be parsed
        config = CiscoConfParse(file)

        # Header
        print("--- Generating report header...")
        generateReportHeader(curr_user, file, out)
        print("Report header generated!")

        # Device Info
        print("--- Generating report device info...")
        version = findVersion(config)
        hostname = findHostname(config)
        intf = findInterfaces(config)
        sh_intf = findShutdownInterfaces(config)
        generateReportDeviceInfo(version, hostname, intf, sh_intf, out)
        print("Report device info generated!")

        # Audit
        print("--- Generating report audit...")
        generateReportAudit(config, version, hostname, intf, sh_intf, out)
        print("Report audit generated!")

        # Footer
        print("--- Generating report footer...")
        generateReportFooter(out)
        print("Report footer generated!")
    except Exception as e:
        # If error in generation, remove existing report and create error report
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
def generateReportDeviceInfo(version, hostname, intf, sh_intf, out):
    out.write("\n# DEVICE INFO\n")
    out.write("Hostname: " + str(" ".join(hostname.text.split()[1:])) + "\n")
    out.write("Version: " + str(" ".join(version.text.split()[1:])) + "\n")
    out.write("Interfaces:\n")
    for i in intf:
        out.write("- " +  str(" ".join(i.split()[1:])) + "\n")
    out.write("Shutdown Interfaces:\n")
    for i in sh_intf:
        out.write("- " + str(" ".join(i.split()[1:])) + "\n")

# Generate audit report
# Gets info from JSON file given the audit check name and section to look for
# Eg. Gets description of "default-hostname" check
def getCheckInfo(file, check, section):
    checks = json.load(open(file, "r"))
    return checks[check][section]

# Includes all audit checks
def generateReportAudit(config, version, hostname, intf, sh_intf, out):
    out.write("\n# AUDIT\n")

    # Default hostname check
    out.write("- DEFAULT HOSTNAME\n")
    if findDefaultHostname(hostname):
        out.write(getCheckInfo("./audit/audit_checks.json", "default-hostname", "description") + "\n")
    else:
        out.write("Hostname is not default.\n")
    
# Generate report footer
# Includes security score and end of report
def generateReportFooter(out):
    out.write("\n# SCORE")
    out.write("\nSecurity Score: NaN\n")
    out.write("\n=== END REPORT ===")
    out.close()
# =========================

# === DEVICE INFO FUNCTIONALITY ===
# Finding version
def findVersion(config):
    print("# Finding version...")
    try:
        version = config.find_objects(['version'])[0]
        print("# Version found!")
        return version
    except IndexError:
        print("# X Unable to find version, IndexError\n" + str(IndexError))
        return "Unable to find version, IndexError\n" + str(IndexError)

# Finding hostname
def findHostname(config):
    print("# Finding hostname...")
    try:
        hostname = config.find_objects(['hostname'])[0]
        print("# Hostname found!")
        return hostname
    except IndexError:
        print("# X Unable to find hostname, IndexError\n" + str(IndexError))
        return "Unable to find hostname, IndexError\n" + str(IndexError)

# Finding interfaces
def findInterfaces(config):
    print("# Finding interfaces...")
    try:
        intfaces = config.find_parent_objects(['interface'])
        print("# Interfaces found!")
        return intfaces
    except IndexError:
        print("# X Unable to find interfaces, IndexError\n" + str(IndexError))
        return ["- Unable to find interfaces in this config file."]

# Finding shutdown interfaces
def findShutdownInterfaces(config):
    print("# Finding shutdown interfaces...")
    try:
        sh_intfaces = config.find_parent_objects(['interface', 'shutdown'])
        if sh_intfaces == []:
            raise Exception("Search returned empty list.")
        print("# Shutdown interfaces found!")
        return sh_intfaces
    except Exception as e:
        print("# X Unable to find shutdown interfaces\n" + str(e))
        return ["- Unable to find shutdown interfaces in this config file."]
# =========================

# === AUDIT FUNCTIONALITY ===
# Finding if hostname is default
def findDefaultHostname(hostname):
    print("# Finding if hostname is default...")
    try:
        if hostname.text.split()[1] == "Router" or hostname.text.split()[1] == "Switch":
            print("# Hostname is default!")
            return True
        else:
            print("# Hostname is not default!")
            return False
    except Exception as e:
        return "# X Unable to find if hostname is default \n" + str(e)
# =========================

# =========================
# Main function
try:
    filepath = sys.argv[1]
    if "\\" in filepath:
        filepath = filepath.replace("\\", "/")
    generateReport("ccart", filepath)
except IndexError:
    print("Usage: python ccart.py <path_to_config>")
    sys.exit(1)