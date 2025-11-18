import socket
import sys

def check_psql_blank(ip, port):
    # Pervasive "Get Version" packet
    get_version_packet = b"\x00\x00\x00\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00"
    
    # Pervasive "Login" packet for user 'Master' with a blank password
    # The 'Master' username (padded) is at offset 0x38
    # The blank password (padded) is at offset 0x69
    login_packet = (
        b"\x00\x00\x00\xc0\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x4d\x61\x73\x74\x65\x72\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        
        # Send Get Version
        s.send(get_version_packet)
        s.recv(1024)
        
        # Send Login
        s.send(login_packet)
        response = s.recv(1024)
        s.close()
        
        # Check response for success
        # A successful login with a blank password will return a response
        # where the 4th byte (status code) is 0x00.
        # A failed login (auth failure) is 0x16.
        if response and len(response) > 4:
            status_code = response[4]
            if status_code == 0x00:
                print(f"[+] SUCCESS: Logged in to {ip}:{port} as 'Master' with a BLANK password.")
            elif status_code == 0x16:
                print(f"[-] FAILED: Login as 'Master' failed (auth error). Not vulnerable to blank pass.")
            else:
                print(f"[?] UNKNOWN: Received unknown status code: {hex(status_code)}")
        else:
            print("[?] FAILED: No valid response from server.")
            
    except Exception as e:
        print(f"[!] ERROR: Could not connect or send data to {ip}:{port}. Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <IP> <PORT>")
        print(f"Example: python3 {sys.argv[0]} 10.1.1.5 1583")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    check_psql_blank(target_ip, target_port)
