Build:
./build.sh

Distribute to a working pineapple with version 2.3:
ssh root@172.16.42.1 "mkdir /tospo"
scp dist/tv* root@172.16.42.1:/tospo/

