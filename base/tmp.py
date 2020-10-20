from importlib import util, import_module
import os
import re
import time

# module_name = "module.manifest.backup"
# metaclass = importlib.import_module(module_name)
# c = metaclass.Module("Test ...")
# c.check()
modules = {}
module_load = []

def check_module(module):
    print(f"[?] Check Module")
    module_spec = util.find_spec(module)
    # print(f"module_spec={module_spec}")
    if module_spec:
        print(f"[√] Module: {module} can be imported.")
    else:
        print(f"[×] Module: {module} not found.")
    return module_spec


for root, _, files in list(os.walk("../module"))[1:]:
    print(root)
    print(files)
    module_type = re.findall(r"module\\(.*)", root)[0]
    if len(files):
        modules[module_type] = ['.'.join(['module', module_type, m[:-3]]) for m in files if m.endswith('py')]


for module_type, modules in modules.items():
    for m in modules:
        if check_module(m):
            aha = import_module(m)
            try:
                obj = aha.Module("aha")
                obj.check()
            except Exception:
                print(f"[!] Load {m} Error.")
            module_load.append(aha)

