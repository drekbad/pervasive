# Create the file: nano test_psql_v2.py
# Paste this code in:

import socket
import sys

def check_psql_blank(ip, port):
    # Pervasive "Get Version" packet
    get_version_packet = b"\x00\x00\x00\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00"
    
    # Pervasive "Login" packet for user 'Master' with a blank password
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

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(15) # <-- Increased timeout
        
        print(f"[*] Connecting to {ip}:{port}...")
        s.connect((ip, port))
        print("[+] Connection successful.")
        
        # Send Get Version
        print("[*] Sending 'Get Version' packet...")
        s.send(get_version_packet)
        version_response = s.recv(1024)
        print(f"[*] Server version response: {version_response.hex()}")

        # Send Login
        print("[*] Sending 'Login' packet for 'Master' (blank pass)...")
        s.send(login_packet)
        login_response = s.recv(1024)
        print(f"[*] Server login response: {login_response.hex()}")
        
        if login_response and len(login_response) > 4:
            status_code = login_response[4]
            if status_code == 0x00:
                print(f"[+] SUCCESS: Logged in to {ip}:{port} as 'Master' with a BLANK password.")
            elif status_code == 0x16:
                print(f"[-] FAILED: Login as 'Master' failed (auth error 0x16). Not vulnerable to blank pass.")
            else:
                print(f"[?] UNKNOWN: Received unknown status code: {hex(status_code)}")
        else:
            print("[?] FAILED: Received no valid login response from server.")
            
    except socket.timeout:
        print(f"[!] ERROR: Connection to {ip}:{port} timed out (15s). Host is likely dropping packets or very slow.")
    except Exception as e:
        print(f"[!] ERROR: An error occurred. {e}")
    finally:
        if s:
            s.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <IP> <PORT>")
        print(f"Example: python3 {sys.argv[0]} 10.1.1.5 1583")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    check_psql_blank(target_ip, target_port)
