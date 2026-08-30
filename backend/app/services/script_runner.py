from scripts.apply_script import run_apply
from scripts.modify_script import run_modify

class ScriptResult:
    def __init__(self, status_code):
        self.status_code = status_code

def run_apply_script():
    print("Executing APPLY SCRIPT...")
    success = run_apply()
    status = 200 if success else 500
    return ScriptResult(status)

def run_modify_script():
    print("Executing MODIFY SCRIPT...")
    success = run_modify()
    status = 200 if success else 500
    return ScriptResult(status)