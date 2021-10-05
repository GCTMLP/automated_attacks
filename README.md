# automated_attacks
automated attacks by scenario via Metasploit Framework and Python

В файле attack_scenario.py находится скрипт, который автоматизирует определенный сценарий атаки. Краткая схема атаки расположена в файле attack.png
Сценарий:

В файле install_mimi.py представлен скрипт автоматизированной загрузки Mimikatz.exe на машину жертвы при помощи Metasploit и уязвимости EnternalBlue. Возвращает вывод команды mimikaz "sekurlsa::logonPasswords".

Для проведения автоматизированных атак необходимо запустить интерфейс msfrpcd, который буде прослушивать определенный порт и предоставлять клиентам, которые к нему подключены, RPC интерфейс к Metasploit Framework.

PS. Скрипты проведенеия других сценариев атак выложу позже
