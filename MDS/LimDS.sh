#!/bin/bash

FILE=$1

if [ -z $1 ]
then
	echo "requires a ELF file as input to scan..."
	echo "usage: ./LimDS <filename>"
	exit 0
else
touch val.txt
chmod 666 val.txt

readelf -h $FILE | awk 'FNR == 11 {print strtonum($4)} FNR == 12{print $5} FNR == 13{print $5} FNR == 15{print $5} FNR == 16{print $5} FNR == 17{print $5} FNR == 18{print $5} FNR == 19{print $5} FNR == 20{print $6}' >> val.txt

EE=$(cat val.txt | awk 'FNR == 1{print $1}')
STPH=$(cat val.txt | awk 'FNR == 2{print $1}')
STSH=$(cat val.txt | awk 'FNR == 3{print $1}')
SE=$(cat val.txt | awk 'FNR == 4{print $1}')
SIPH=$(cat val.txt | awk 'FNR == 5{print $1}')
NPH=$(cat val.txt | awk 'FNR == 6{print $1}')
SISH=$(cat val.txt | awk 'FNR == 7{print $1}')
NSH=$(cat val.txt | awk 'FNR == 8{print $1}')
SHS=$(cat val.txt | awk 'FNR == 9{print $1}')

spin() {
	local -a marks=( '/' '-' '\' '|' );
    	for (( j = 0 ; j < 21 ; j++ )); do
	echo -n "${marks[i++ % ${#marks[@]}]}";
      		sleep 0.7;
      	echo -ne "\b";
    done;  
}


compare() {
	if [ "$EE" -le 134515376 ] && [ "$NSH" -le 29 ] && [ "$NPH" -ge 9 ] && [ "$SISH" -ge 64 ] && [ "$SHS" -le 28 ];then
		echo "The file examined is not a Malware"
		echo "*"
	else
		echo "Malware File Detected !!!"
		echo "*"
	fi
}

echo "*"; echo "Comparing with the trained model...";sleep 0.8; echo "*"; sleep 0.8;

spin
compare

truncate -s 0 val.txt
chmod 000 val.txt
rm -rf val.txt
fi
