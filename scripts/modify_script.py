import json
from datetime import datetime, timezone
from deepdiff import DeepDiff
from scripts.utils import get_rbac_state, load_yaml, save_yaml

def run_modify(baseline_file="baseline.yaml", current_file="current.yaml", diff_file="rbac_diff.yaml"):
    """Fetches current RBAC state, compares it against baseline.yaml excluding metadata, and records drift in rbac_diff.yaml."""
    print("Running Modify Script: Fetching current RBAC state & checking for drift...")
    try:
        baseline_state = load_yaml(baseline_file)
        if not baseline_state:
            print(f"Warning: '{baseline_file}' is missing or empty. Please run apply_script.py first.")

        current_state = get_rbac_state()
        current_state["_guardian_metadata"] = {
            "latest_edit": datetime.now(timezone.utc).strftime("%Y-%m-%d-%H:%MUTC")
        }
        save_yaml(current_state, current_file)

        diff = DeepDiff(
            baseline_state, 
            current_state, 
            ignore_order=True,
            verbose_level=2,
            exclude_paths=["root['_guardian_metadata']"]
        )

        if diff:
            diff_dict = json.loads(diff.to_json())
            diff_dict["_guardian_metadata"] = {
                "drift_detected_at": datetime.now(timezone.utc).strftime("%Y-%m-%d-%H:%MUTC")
            }
            save_yaml(diff_dict, diff_file)
            print(f"Drift detected! Differences saved to '{diff_file}'.")
        else:
            save_yaml({
                "status": f"No differences found at {datetime.now(timezone.utc).strftime('%Y-%m-%d-%H:%MUTC')}"
            }, diff_file)
            print("No RBAC drift detected between current cluster state and baseline.")
        return True
    except Exception as e:
        print(f"Error executing modify script: {e}")
        return False

if __name__ == "__main__":
    run_modify()
