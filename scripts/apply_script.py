from datetime import datetime, timezone
from scripts.utils import get_rbac_state, save_yaml

def run_apply(baseline_file="baseline.yaml"):
    """Fetches live cluster RBAC state and updates baseline.yaml with timezone-aware timestamp metadata."""
    print("Running Apply Script: Fetching Kubernetes RBAC state...")
    try:
        rbac_state = get_rbac_state()
        rbac_state["_guardian_metadata"] = {
            "latest_apply": datetime.now(timezone.utc).strftime("%Y-%m-%d-%H:%MUTC")
        }
        save_yaml(rbac_state, baseline_file)
        print(f"Successfully updated baseline state in '{baseline_file}'.")
        return True
    except Exception as e:
        print(f"Error executing apply script: {e}")
        return False

if __name__ == "__main__":
    run_apply()
