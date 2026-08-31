import os
import yaml

def save_yaml(data, filepath) -> None:
    """Saves dictionary data to a YAML file."""
    with open(filepath, 'w', encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=True)

def load_yaml(filepath) -> dict:
    """Loads dictionary data from a YAML file."""
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}
