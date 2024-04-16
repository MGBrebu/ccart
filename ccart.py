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

# === REPORT GENERATION FUNCTIONALITY ===
# Main report function generates report using header, footer, and all findings functions
def generateReport(user, file):
    # Datetime Init
    dt = datetime.now()
    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"### Generating report for {file.split('/')[-1]} at {timestamp}...") # Logging

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
        print("Generating report header...") # Logging
        generateReportHeader(curr_user, timestamp, file, out)

        # Device Info
        print("Generating device info...") # Logging
        version = findVersion(config)
        hostname = findHostname(config)
        intf = findInterfaces(config)
        sh_intf = findShutdownInterfaces(config)
        generateReportDeviceInfo(version, hostname, intf, sh_intf, out)

        # Audit
        print("Generating audit report...") # Logging
        generateReportAudit(config, version, hostname, intf, sh_intf, out)

        # Footer
        print("Generating report footer...") # Logging
        generateReportFooter(out)
    except Exception as e:
        # If error in generation, remove existing report and create error report
        out.close()
        os.remove(f"./output/{reportName}")
        open('./output/' + "error_" + reportName, 'w').write(f"Error generating report:\n {e}")
        print(f"### Error generating report:\n {e}")

    print(f"### Report generated!") # Logging

# Generate report header
# Includes datetime, current user*, and current config file
# * Placeholder for future implementation
def generateReportHeader(curr_user, timestamp, file, out):
    out.write("=== BEGIN REPORT ===\n")
    out.write("# REPORT INFO\n")
    out.write("Date/Time Generated: " + timestamp + "\n")
    out.write("Current User: " + curr_user + "\n")
    out.write("Configuration File: " + file + "\n")

    print("Report header generated!") # Logging

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
    
    print("Device info generated!") # Logging

# Generate audit report
# Getimestamp info from JSON file given the audit check name and section to look for
# Eg. Getimestamp description of "default-hostname" check
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
        out.write(getCheckInfo("./audit/audit_checks.json", "default-hostname", "remediation") + "\n")
    else:
        out.write("Hostname is not default.\n")

    # Password Encryption enabled check
    out.write("- PASSWORD ENCRYPTION\n")
    if findPasswordEncryption(config):
        out.write("Password encryption service is enabled.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "password-encryption", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "password-encryption", "remediation") + "\n")

    print("Audit report generated!") # Logging
    
# Generate report footer
# Includes security score and end of report
def generateReportFooter(out):
    out.write("\n# SCORE")
    out.write("\nSecurity Score: NaN\n")
    out.write("\n=== END REPORT ===")
    out.close()

    print("Report footer generated!") # Logging
# =========================

# === DEVICE INFO FUNCTIONALITY ===
# Finding version
def findVersion(config):
    print(" # Finding version...") # Logging
    try:
        version = config.find_objects(['version'])[0]
        print(" Version found!") # Logging
        return version
    except IndexError:
        print(" X Unable to find version, IndexError\n" + str(IndexError)) # Logging
        return "X Unable to find version, IndexError\n" + str(IndexError)

# Finding hostname
def findHostname(config):
    print(" # Finding hostname...") # Logging
    try:
        hostname = config.find_objects(['hostname'])[0]
        print(" Hostname found!") # Logging
        return hostname
    except IndexError:
        print(" X Unable to find hostname, IndexError\n" + str(IndexError)) # Logging
        return "X Unable to find hostname, IndexError\n" + str(IndexError)

# Finding interfaces
def findInterfaces(config):
    print(" # Finding interfaces...") # Logging
    try:
        intfaces = config.find_parent_objects(['interface'])
        print(" Interfaces found!") # Logging
        return intfaces
    except IndexError:
        print(" X Unable to find interfaces, IndexError\n" + str(IndexError)) # Logging
        return ["X Unable to find interfaces in this config file."]

# Finding shutdown interfaces
def findShutdownInterfaces(config):
    print(" # Finding shutdown interfaces...") # Logging
    try:
        sh_intfaces = config.find_parent_objects(['interface', 'shutdown'])
        if sh_intfaces == []:
            raise Exception("Search returned empty list.")
        print(" Shutdown interfaces found!") # Logging
        return sh_intfaces
    except Exception as e:
        print(" X Unable to find shutdown interfaces\n" + str(e)) # Logging
        return ["X Unable to find shutdown interfaces in this config file."]
# =========================

# === AUDIT FUNCTIONALITY ===
# Finding if hostname is default
def findDefaultHostname(hostname):
    print(" # Finding if hostname is default...") # Logging
    try:
        if hostname.text.split()[1] == "Router" or hostname.text.split()[1] == "Switch":
            print(" Hostname is default!") # Logging
            return True
        else:
            print(" Hostname is not default!") # Logging
            return False
    except Exception as e:
        print(" X Unable to find if hostname is default\n" + str(e))  # Logging
        return "X Unable to find if hostname is default \n" + str(e)
    
# Finding if password encryption service is enabled
def findPasswordEncryption(config):
    print(" # Finding if password encryption service is enabled...") # Logging
    try:
        pass_encryption = config.find_objects(['service password-encryption'])
        if (" ".join(pass_encryption[0].split()[:1])) == "no":
            print(" Password encryption service is not enabled!") # Logging
            return False
        else:
            print(" Password encryption service is enabled!") # Logging
            return True
    except Exception as e:
        print(" X Unable to find if password encryption service is enabled\n" + str(e))  # Logging
        return "X Unable to find if password encryption service is enabled\n" + str(e)
    
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