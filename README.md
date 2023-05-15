# automated_attacks
automated attacks by scenario via Metasploit Framework and Python

The attack_scenario.py file contains a script that automates a specific attack scenario. A brief attack scheme is located in the attack.png file

The install_mimi.py file contains a script for automatically downloading Mimikatz.exe to the victim machine using Metasploit and the EnternalBlue vulnerability. Returns the output of the mimikaz command "sekurlsa::logonPasswords"

To carry out automated attacks, you need to run the msfrpcd interface, which will listen on a specific port and provide clients that are connected to it with an RPC interface to the Metasploit Framework.

