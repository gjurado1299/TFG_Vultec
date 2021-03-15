#!/bin/bash

PATH_RES="/home/kali/UNIVERSIDAD/TFG/Vultec/scans"
NUCLEI_TMP="/home/kali/nuclei-templates"
TLD=$1


nuclei -l $(cat $PATH_RES/$TLD/webalives.txt | cut -d " " -f1) -t $NUCLEI_TMP/cves -t $NUCLEI_TMP/vulnerabilities \
-t $NUCLEI_TMP/exposures -t $NUCLEI_TMP/exposed-panels -t $NUCLEI_TMP/exposed-tokens -t $NUCLEI_TMP/default-logins \
-t $NUCLEI_TMP/misconfiguration -t $NUCLEI_TMP/takeovers -t $NUCLEI_TMP/technologies \
-c 300 -bulk-size 500 -rate-limit 1200 -timeout 12 -retries 2 -silent -o $PATH_RES/$TLD/nuclei-results_draft.txt &> /dev/null;