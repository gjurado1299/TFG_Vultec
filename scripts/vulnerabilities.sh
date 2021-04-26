#!/bin/bash

PATH_RES="/home/gonxo/Vultec/scans"
NUCLEI_TMP="/home/gonxo/nuclei-templates"
TLD=$1

nuclei -silent -update-templates

if [ ! -f $PATH_RES/$TLD/nuclei_results_draft.txt ]; then
    touch $PATH_RES/$TLD/nuclei_results_draft.txt
fi

nuclei -l $PATH_RES/$TLD/webalives_scan.txt -t $NUCLEI_TMP/cves -t $NUCLEI_TMP/vulnerabilities \
-t $NUCLEI_TMP/exposures -t $NUCLEI_TMP/exposed-panels -t $NUCLEI_TMP/exposed-tokens -t $NUCLEI_TMP/default-logins \
-t $NUCLEI_TMP/misconfiguration -t $NUCLEI_TMP/takeovers -t $NUCLEI_TMP/technologies \
-c 300 -bulk-size 500 -rate-limit 1200 -timeout 12 -retries 2 -silent -json -o $PATH_RES/$TLD/nuclei_results_draft.txt &> /dev/null;