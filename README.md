Build:
./build.sh

Distribute to a working pineapple with version 2.3:

ssh -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null root@172.16.42.1 "mkdir /tospo"

scp -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null dist/tv* root@172.16.42.1:/tospo/

Decrypting ex-filtrated data:

printf $(echo "$1" | sed -re 's/(..)/\\x\1/g') | openssl rsautl -decrypt -inkey tvd.pem