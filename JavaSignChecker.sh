#!/bin/sh
##TO DO - formatting, output file, stats, pretty colours. Maybe an array to put the signed and unsigned file names in.

echo "=========JAVA CHECKER========"
echo "\n"
for i in $(find . -iname "*.jar");
	do
	echo $i
	jarsigner -verify -certs $i
	echo "\n\n"
done

echo "All finished :)"
