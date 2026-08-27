class ScriptResult:
    def __init__(self, status_code):
        self.status_code = status_code


def run_apply_script():
    print("APPLY SCRIPT RAN")
    return ScriptResult(200)


def run_modify_script():
    print("MODIFY SCRIPT RAN")
    return ScriptResult(200)