import subprocess

def os_system(command):
    process = subprocess.run(command, shell=True, capture_output=True)
    output = process.stdout + process.stderr
    print(output.decode())

import os
os.system = os_system

# =============== CUT HERE =====================

# THIS DOESNT WORK!! yet...
from importlib.abc import SourceLoader
import importlib.util
import sys

class FilelessSourceLoader(SourceLoader):
    def __init__(self, module_name, source):
        self.source_bytes = source
        self.name = module_name
        super().__init__()

    def get_data(self, path):
        return self.source_bytes

    def get_filename(self, fullname):
        return ""

# THIS ONLY WORKS HALF yet...
def import_module_from_source(module_name, source):
    loader = FilelessSourceLoader(module_name, source)
    spec = importlib.util.spec_from_loader(module_name, loader)
    module_object = importlib.util.module_from_spec(spec)
    loader.exec_module(module_object)
    sys.modules[module_name] = module_object
    globals()[module_name] = module_object
    locals()[module_name] = module_object

# DEBUG ONLY!!
def import_module_from_path(name, path):
    with open(path, "rb") as f:
        import_module_from_source(name, f.read())

