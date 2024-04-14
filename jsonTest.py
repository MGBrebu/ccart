import json

def getCheckInfo(file, check, section):
    checks = json.load(open(file, "r"))
    return checks[check][section]

print(getCheckInfo("./audit/audit_checks.json", "default-hostname", "description"))