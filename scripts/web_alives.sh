#!/bin/bash

PATH_RES="/home/gonxo/Vultec/scans"
TLD=$1
cat $PATH_RES/$TLD/subdomains.txt | httpx -no-color -status-code -title -content-length -ip -cname -web-server -tech-detect -silent -ports \
    80,443,8000,8080 -timeout 5 -threads 300 -json > $PATH_RES/$TLD/webalives.txt
