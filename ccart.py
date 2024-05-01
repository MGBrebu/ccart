import sys
import os
import json
from datetime import datetime
from ciscoconfparse2 import CiscoConfParse

# ------------------------------------------------
# Cisco Configuration Auditing and Reporting Tool
# By Mario Brebu, Daniel Baldwin, and Mataz Al-Mashikhi
# In collaboration with greater Configuroo web application project
# ------------------------------------------------

# Init score
score = 0

# === REPORT GENERATION FUNCTIONALITY ===
# # Main report function 
# Generates report using header, footer, and all findings functions
def generateReport(user, file):
    

    # Init Datetime
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

    # Get global score, max score, and create report details dict to return relevant report values
    global score
    maxScore = getCheckCount("./audit/audit_checks.json")
    reportDetails = {"name": reportName, "score": score, "max-score": maxScore}

    # Reset score after each report
    score = 0
    
    return reportDetails

# # Generate report header
# Includes datetime, current user*, and current config file
# * Placeholder for future implementation
def generateReportHeader(curr_user, timestamp, file, out):
    out.write("\n======= BEGIN REPORT =======\n\n")
    out.write("# REPORT INFO\n")
    out.write("Date/Time Generated: " + timestamp + "\n")
    out.write("Current User: " + curr_user + "\n")
    out.write("Configuration File: " + file + "\n")

    print("Report header generated!") # Logging

# # Generate device info
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

# # Generate audit report
# Includes all audit checks
def generateReportAudit(config, version, hostname, intf, sh_intf, out):
    out.write("\n# AUDIT\n")

    # Default hostname check
    out.write("\n- DEFAULT HOSTNAME\n")
    if findDefaultHostname(hostname):
        out.write(getCheckInfo("./audit/audit_checks.json", "default-hostname", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "default-hostname", "remediation") + "\n")
    else:
        out.write("Hostname is not default.\n")
    
    # Banner MOTD check
    out.write("\n- BANNER MOTD\n")
    if findBanner(config):
        out.write(getCheckInfo("./audit/audit_checks.json", "banner-motd", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "banner-motd", "remediation") + "\n")
    else:
        out.write("Banner MOTD is appropriately configured.\n")

    # Password Encryption enabled check
    out.write("\n- PASSWORD ENCRYPTION\n")
    if findPasswordEncryption(config):
        out.write("Password encryption service is enabled.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "password-encryption", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "password-encryption", "remediation") + "\n")

    # Enable password (non-secret) check
    out.write("\n- ENABLE PASSWORD (NON-SECRET)\n")
    if checkEnablePassword(config):
        out.write("Enable password (non-secret) is set.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "enable-password", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "enable-password", "remediation") + "\n")

    # Enable secret check
    out.write("\n- ENABLE SECRET\n")
    if checkEnableSecret(config):
        out.write("Enable secret is set.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "enable-secret", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "enable-secret", "remediation") + "\n")
    
    # Native VLAN
    out.write("\n- Native VLAN\n")
    if checkNativeVLAN(config):
        out.write("Native VLAN is not set to VLAN 1.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "Native-VLAN", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "Native-VLAN", "remediation") + "\n")

     # ACL
    out.write("\n- ACL\n")
    if checkACLConfig(config):
        out.write("ACLs are configured.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "acl-configuration", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "acl-configuration", "remediation") + "\n")

    # Unrestricted access in ACLs check
    out.write("\n- UNRESTRICTED ACCESS IN ACLS\n")
    if checkUnrestrictedAccess(config):
        out.write("No unrestricted access found in ACLs.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "unrestricted-access", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "unrestricted-access", "remediation") + "\n")
    # Traffic Encryption
    out.write("\n- TRAFFIC ENCRYPTION\n")
    if checkRSAKeyGeneration(config):
        out.write("Traffic encryption is enabled.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "traffic-encryption", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "traffic-encryption", "remediation") + "\n")

    # SSH Configuration
    out.write("\n- SSH CONFIGURATION\n")
    if checkSSHConfiguration(config):
        out.write("SSH configuration is present.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "ssh-configuration", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "ssh-configuration", "remediation") + "\n")
        
    # Enable VTY inbound SSH sessions
    out.write("\n- ENABLE VTY INBOUND SSH SESSIONS\n")
    if checkEnableVTYSSH(config):
        out.write("VTY inbound SSH sessions are enabled.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "enable-vty-ssh-sessions", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "enable-vty-ssh-sessions", "remediation") + "\n")
        
    # Port Security
    out.write("\n- PORT SECURITY\n")
    if switchPortSecurity(config):
        out.write("Port security is configured.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "port-security", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "port-security", "remediation") + "\n")

    # AAA Authentication
    out.write("\n- AAA AUTHENTICATION\n")
    if checkAAAAuthentication(config):
        out.write("AAA authentication is configured.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "aaa-authentication", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "aaa-authentication", "remediation") + "\n")

    # Timestamp logging
    out.write("\n- TIMESTAMP LOGGING\n")
    if checkTimestamp(config):
        out.write("Timestamp logging is configured.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "timestamp-logging", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "timestamp-logging", "remediation") + "\n")
        
    #check for HTTPS secure-server
    out.write("\n- HTTPS SECURE-SERVER\n")
    if checkHTTPSecureServer(config):
        out.write("HTTPS Secure-server is configured\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "https-secure-server", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "https-secure-server", "remediation") + "\n")
        
    # Central Logging
    out.write("\n- CENTRAL LOGGING\n")
    if checkCentralLogging(config):
        out.write("Central logging is configured.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "central-logging", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "central-logging", "remediation") + "\n")
        
    # NTP server configuration
    out.write("\n- NTP SERVER CONFIGURATION\n")
    if checkNTPConfiguration(config):
        out.write("NTP server configuration is present.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "ntp-configuration", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "ntp-configuration", "remediation") + "\n")
        
     # AutomationSecurity
    out.write("\n- IOS IMAGE RESILIENCE FEATURE\n")
    if checkIOSImageResilience(config):
        out.write("\nIOS Image Resilience Feature is enabled.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "ios-image-resilience", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "ios-image-resilience", "remediation") + "\n")

    # Snapshot configuration
    out.write("\n- SNAPSHOT CONFIGURATION\n")
    if checkSnapshotConfiguration(config):
        out.write("Snapshot configuration is present.\n")
    else:
        out.write(getCheckInfo("./audit/audit_checks.json", "snapshot-configuration", "description") + "\n")
        out.write(getCheckInfo("./audit/audit_checks.json", "snapshot-configuration", "remediation") + "\n")
        
    print("\nAudit report generated!") # Logging
    
# Generate report footer
# Includes security score and end of report
def generateReportFooter(out):
    out.write("\n# SCORE")
    out.write("\nSecurity Score: " + str(str(getScore()) + " / " + str(getCheckCount("./audit/audit_checks.json"))))
    out.write("\n\n======= END REPORT =======\n\n")
    out.close()

    print("Report footer generated!") # Logging
# =========================

# === DEVICE INFO FUNCTIONALITY ===
# Device info functions get basic info about device from config file
# These are not audit checks, but are used in audit checks

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
    
# Finding unused interfaces
def findUnusedInterfaces(config):
    print(" # Finding unused interfaces...") # Logging
    try:
        unused_intfaces = config.find_objects(['interface', 'no', 'shutdown'])
        print(" Unused interfaces found!") # Logging
        return unused_intfaces
    except IndexError:
        print(" X Unable to find unused interfaces, IndexError\n" + str(IndexError)) # Logging
        return ["X Unable to find unused interfaces in this config file."] 
# ===========================

# === AUDIT FUNCTIONALITY ===
# Audit functions grab score from global scope, perform audit check, and increment score if passed

# Finding if hostname is default
def findDefaultHostname(hostname):
    global score # Grabbing score
    print(" # Finding if hostname is default...") # Logging
    try:
        if hostname.text.split()[1] == "Router" or hostname.text.split()[1] == "Switch":
            print(" -Hostname is default!") # Logging
            return True
        else:
            print(" +Hostname is not default!") # Logging
            score += 1 # Scoring
            return False
    except Exception as e:
        print(" X Unable to find if hostname is default\n" + str(e))  # Logging
        return "X Unable to find if hostname is default \n" + str(e)
    
# Finding if the password encryption service is enabled
def findPasswordEncryption(config):
    global score # Grabbing score
    print(" # Finding if password encryption service is enabled...") # Logging
    try:
        pass_encryption = config.find_objects(['service password-encryption'])
        if (" ".join(pass_encryption[0].split()[:1])) == "no":
            print(" -Password encryption service is not enabled!") # Logging
            return False
        else:
            print(" +Password encryption service is enabled!") # Logging
            score += 1 # Scoring
            return True
    except Exception as e:
        print(" X Unable to find if password encryption service is enabled\n" + str(e))  # Logging
        return "X Unable to find if password encryption service is enabled\n" + str(e)
    
# Finding if the enable password (non-secret) is set
def checkEnablePassword(config):
    global score # Grabbing score
    print(" # Finding if enable password (non-secret) is set...") # Logging
    try:
        enable_pass = config.find_objects(['enable password'])
        if enable_pass:
            print(" +Enable password (non-secret) is set!") # Logging
            score += 1 # Scoring
            return True
        else:
            print(" -Enable password (non-secret) is not set!") # Logging
            return False
    except Exception as e:
        print(" X Unable to find if enable password (non-secret) is set\n" + str(e))  # Logging
        return "X Unable to find if enable password (non-secret) is set\n" + str(e)
    
# Finding if the enable secret password is set
def checkEnableSecret(config):
    global score # Grabbing score
    print(" # Finding if enable secret is set...") # Logging
    try:
        enable_secret = config.find_objects(['enable secret'])
        if enable_secret:
            print(" +Enable secret is set!") # Logging
            score += 1 # Scoring
            return True
        else:
            print(" -Enable secret is not set!") # Logging
            return False
    except Exception as e:
        print(" X Unable to find if enable secret is set\n" + str(e))  # Logging
        return "X Unable to find if enable secret is set\n" + str(e)
    
# Finding the native vlan and check if it is set to defualt (vlan 1)
def checkNativeVLAN(config):
    global score # grabbing score
    print ("#check for vlan ") #logging
    try:
        native_vlan = config.find_objects(r'interface\s+\S+')[0].re_match_iter_typed(r"switchport trunk native vlan\s+(\d+)")
        if native_vlan:
            if native_vlan[0] == '1':
                print(" +Native VLAN is set to VLAN 1!") # Logging
                score += 0 # Scoring
                return False
            else:
                print(" -Native VLAN is not set to VLAN 1!") # Logging
                score += 1 # Scoring
                return True
        else:
            print(" X Unable to find native VLAN configuration!") # Logging
            return "X Unable to find native VLAN configuration!"
    except Exception as e:
        print(" X Error finding native VLAN configuration\n" + str(e))  # Logging
        return "X Error finding native VLAN configuration\n" + str(e)

# check if standard and extended ACLs are configured
def checkACLConfig(config):
    print(" # Checking if ACLs are configured...") # Logging
    try:
        standard_acls = config.find_objects(r'access-list')
        extended_acls = config.find_objects(r'ip access-list')
        
        if standard_acls or extended_acls:
            print(" +ACLs are configured!") # Logging
            return True
        else:
            print(" -No ACLs are configured!") # Logging
            return False
    except Exception as e:
        print(" X Error checking ACL configuration\n" + str(e))  # Logging
        return "X Error checking ACL configuration\n" + str(e)
        
# Finding unrestricted access in ACLs
def checkUnrestrictedAccess(config):
    global score # grabbing score
    print ("#check for unrestricted access in ACLs") #logging
    try:
        acls = config.find_objects(['access-list'])
        for acl in acls:
            if 'permit ip any any' in acl.text:
                print(" -Unrestricted access found in ACL!") # Logging
                score += 1 # Scoring
                return False
        print(" +No unrestricted access found in ACLs!") # Logging
        return True
    except Exception as e:
        print(" X Error finding unrestricted access in ACLs\n" + str(e))  # Logging
        return "X Error finding unrestricted access in ACLs\n" + str(e)

# Finding banner motd
def findBanner(config):
    print(" # Finding banner motd...") # Logging
    sensitive_words = ['password', 'user', 'admin', 'root', 'secret']
    warning_words = ['unauthorised', 'unauthorized', 'prohibited', 'legal', 'illegal', 'warning', 'alert']
    try:
        banner = config.find_objects(['banner'])[0]
        if banner:
            print("Banner found!")  # Logging
            banner_text = " ".join(banner[0].text.split()[3:])
            has_sensitive_info = any(word in banner_text for word in sensitive_words)
            has_warning = any(word in banner_text for word in warning_words)
            if has_sensitive_info: print("Sensitive words found in banner!")
            if not has_warning: print("No legal warning found in banner!")
            if not has_sensitive_info and has_warning:
                print("Banner is appropriately configured!")
                return True
            else:
                print("Issue with banner configuration!")
                return False
        else:
            print("No banner located!")
            return "No banner located!"
    except Exception as e:
        print(" X Error when searching for banner. IndexError\n" + str(e))  # Logging
        return [" X Error when searching for banner. IndexError"]
    
# Finding timestamp configuration
def checkTimestamp(config):
    global score  # grabbing score
    print(" # Checking timestamp configuration...")  # Logging
    try:
        timestamp_config = config.find_objects(r'service timestamps log datetime msec')
        if timestamp_config:
            print(" +Timestamp configuration found!")  # Logging
            score += 1  # Scoring
            return True
        else:
            print(" -Timestamp configuration not found!")  # Logging
            return False
    except Exception as e:
        print(" X Error checking timestamp configuration\n" + str(e))  # Logging
        return "X Error checking timestamp configuration\n" + str(e)
    
# Check for sending logs to a central location using logging host
def checkCentralLogging(config):
    global score  # grabbing score
    print(" # Checking sending logs to a central location...")  # Logging
    try:
        logging_host_config = config.find_objects('logging host')
        
        if logging_host_config:
            print(" +Logging host configuration found!")  # Logging
            score += 1  # Scoring
            return True
        else:
            print(" -Logging host configuration not found!")  # Logging
            return False
    except Exception as e:
        print(" X Error checking logging host configuration\n" + str(e))  # Logging
        return "X Error checking logging host configuration\n" + str(e)

# Check AAA Authentication configuration
def checkAAAAuthentication(config):
    global score  # grabbing score
    print(" # Checking AAA Authentication configuration...")  # Logging
    try:
        aaa_auth_config = config.find_objects(r'aaa authentication')
        if aaa_auth_config:
            print(" +AAA Authentication configuration found!")  # Logging
            score += 1  # Scoring
            return True
        else:
            print(" -AAA Authentication configuration not found!")  # Logging
            return False
    except Exception as e:
        print(" X Error checking AAA Authentication configuration\n" + str(e))  # Logging
        return "X Error checking AAA Authentication configuration\n" + str(e)
# Check switchport security configuration including violation modes and sticky MAC addresses
def switchPortSecurity(config):
    global score  # grabbing score
    print(" # Checking switchport security configuration...")  # Logging
    try:
        switchport_security_config = config.find_objects('switchport port-security')
        if switchport_security_config:
            print(" +Switchport security configuration found!")  # Logging
            score += 1  # Scoring
            return True
        else:
            print(" -Switchport security configuration not found!")  # Logging
            return False
    except Exception as e:
        print(" X Error checking switchport security configuration\n" + str(e))  # Logging
        return "X Error checking switchport security configuration\n" + str(e)

# Check for RSA key generation **/encryption for remote connection/**
def checkRSAKeyGeneration(config):
    global score  # grabbing score
    print(" # Checking RSA key generation...")  # Logging
    try:
        rsa_modulus_config = config.find_objects('crypto key generate rsa modulus')
        
        if rsa_modulus_config:
            print(" +RSA key generation found!")  # Logging
            score += 1  # Scoring
            return True
        else:
            print(" -RSA key generation not found!")  # Logging
            return False
    except Exception as e:
        print(" X Error checking RSA key generation\n" + str(e))  # Logging
        return "X Error checking RSA key generation\n" + str(e)

# find SSH configuration for session time-out and Authentication retries
def checkSSHConfiguration(config):
    global score  # grabbing score
    print(" # Checking SSH configuration...")  # Logging
    try:
        ssh_config_timeout = config.find_objects(r'ip\sssh\stimeout')
        ssh_config_retries = config.find_objects(r'ip\sssh\sauthentication-retries')

        if ssh_config_timeout:
            print(" +SSH timeout configuration found!")  # Logging
            score += 1  # Scoring

        if ssh_config_retries:
            print(" +SSH authentication retries configuration found!")  # Logging
            score += 1  # Scoring

        if ssh_config_timeout or ssh_config_retries:
            return True
        else:
            print(" -SSH configuration not found!")  # Logging
            return False
    except Exception as e:
        print(" X Error checking SSH configuration\n" + str(e))  # Logging
        return "X Error checking SSH configuration\n" + str(e)
    
# Find HTTPS secure-server configuration 
def checkHTTPSecureServer(config):
    global score  # grabbing score
    print(" # Checking HTTP Secure Server configuration...")  # Logging
    try:
        http_secure_server_config = config.find_objects('ip http secure-server')
        if http_secure_server_config:
            print(" +HTTP Secure Server configuration found!")  # Logging
            score += 1  # Scoring
            return True
        else:
            print(" -HTTP Secure Server configuration not found!")  # Logging
            return False
    except Exception as e:
        print(" X Error checking HTTP Secure Server configuration\n" + str(e))  # Logging
        return "X Error checking HTTP Secure Server configuration\n" + str(e)
    
# Check if ssh enabled in vty line Only
def checkEnableVTYSSH(config):
    global score  # grabbing score
    print(" # Checking enablement of VTY inbound SSH sessions...")  # Logging
    try:
        ssh_vty_config = config.find_objects('line vty 0 \d\n(.*\n)*\s*transport input ssh')
        if ssh_vty_config:
            print(" +VTY inbound SSH sessions are enabled!")  # Logging
            score += 1  # Scoring
            return True
        else:
            print(" -VTY inbound SSH sessions are not enabled!")  # Logging
            return False
    except Exception as e:
        print(" X Error checking enablement of VTY inbound SSH sessions\n" + str(e))  # Logging
        return "X Error checking enablement of VTY inbound SSH sessions\n" + str(e)

# Finding NTP server configuration
def checkNTPConfiguration(config):
    global score  # grabbing score
    print(" # Checking NTP server configuration...")  # Logging
    try:
        ntp_config = config.find_objects('ntp server')
        if ntp_config:
            print(" +NTP server configuration found!")  # Logging
            score += 1  # Scoring
            return True
        else:
            print(" -NTP server configuration not found!")  # Logging
            return False
    except Exception as e:
        print(" X Error checking NTP server configuration\n" + str(e))  # Logging
        return "X Error checking NTP server configuration\n" + str(e)
# Finding IOS Image Resilience (Security Automation)
def checkIOSImageResilience(config):
    global score  # grabbing score
    print(" # Checking IOS Image Resilience Feature configuration...")  # Logging
    try:
        secure_boot_image = config.find_objects('secure boot-image')
        if secure_boot_image:
            print(" +IOS Image Resilience Feature configuration found!")  # Logging
            score += 1  # Scoring
            return True
        else:
            print(" -IOS Image Resilience Feature configuration not found!")  # Logging
            return False
    except Exception as e:
        print(" X Error checking IOS Image Resilience Feature configuration\n" + str(e))  # Logging
        return "X Error checking IOS Image Resilience Feature configuration\n" + str(e)
    
# Check for running-config Snapshots
def checkSnapshotConfiguration(config):
    global score  # grabbing score
    print(" # Checking snapshot configuration...")  # Logging
    try:
        secure_boot_config = config.find_objects('secure boot-config')
        if secure_boot_config:
            print(" +Snapshot configuration found!")  # Logging
            score += 1  # Scoring
            return True
        else:
            print(" -Snapshot configuration not found!")  # Logging
            return False
    except Exception as e:
        print(" X Error checking snapshot configuration\n" + str(e))  # Logging
        return "X Error checking snapshot configuration\n" + str(e)
# =========================

# === GENERAL FUNCTIONS ===
# Importing JSON file function, general purpose so can swap out audit check JSONs if need be
def importJson(file):
    return json.load(open(file, "r"))

# Returns amount of checks in given JSON file, basically enumerates all checks
# For scoring out of total checks
def getCheckCount(file, checkCount = 0):
    for c in importJson(file):
        checkCount += 1
    return checkCount

# Use importJson() to grab specific audit check info given check name and section to search
# Eg. Get "description" of "default-hostname" check
def getCheckInfo(file, check, section):
    data = importJson(file)
    return data[check][section]

# Returns score from global scope
def getScore():
    global score
    return score
# =========================

# === Main Function ===
try:
    filepath = sys.argv[1]
    if "\\" in filepath:
        filepath = filepath.replace("\\", "/")
    reportName = "./output/" + generateReport("ccart", filepath)["name"]
    print(f"Report generated at {reportName}")

except IndexError:
    print("Usage: python ccart.py <path_to_config>")
    sys.exit(1)