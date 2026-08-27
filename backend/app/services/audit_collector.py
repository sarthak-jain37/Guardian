import json, yaml

def collect_audit_logs():
    
    # Read audit logs from Kubernetes
    # Format them
    # Return structured data
    with open("audit.json", "r") as f:
            data = json.load(f)
        
    return data