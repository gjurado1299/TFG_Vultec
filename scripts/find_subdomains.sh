#!/bin/bash

YELLOW='\033[1;33m'
LIGHT_G='\033[1;32m'
LIGHT_B='\033[1;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

PATH_RES="/home/gonxo/Vultec/scans"
PATH_OFA=$(find ~ -name "OneForAll")

################################ Tool functions ################################
AssetFinder(){
    echo -e "${YELLOW}Running ${LIGHT_G}AssetFinder${YELLOW}...${NC}"
    assetfinder --subs-only $1 2>/dev/null > $PATH_RES/$domain_selected/subdomains_AssetFinder.txt;
}

SubFinder(){
    echo -e "${YELLOW}Running ${LIGHT_G}SubFinder${YELLOW}...${NC}"
    subfinder -d $1 -recursive -silent -t 200 -o $PATH_RES/$domain_selected/subdomains_SubFinder.txt &> /dev/null;
}

Amass(){
    echo -e "${YELLOW}Running ${LIGHT_G}Amass${YELLOW}...${NC}"
    amass enum -nolocaldb -passive -timeout 10 -silent -min-for-recursive 2 -d $1 -o $PATH_RES/$domain_selected/subdomains_Amass.txt &> /dev/null;
}

OneForAll(){
    echo -e "${YELLOW}Running ${LIGHT_G}OneForAll${YELLOW}...${NC}"

    python3 $PATH_OFA/oneforall.py --target $1 --dns False --req False --format csv run &> /dev/null;
    cat $PATH_OFA/results/$1.csv | cut -d ',' -f6 > $PATH_RES/$domain_selected/subdomains_OneForAll.txt;
}
#################################################################################


############################# The command line help #############################
display_help() {
    echo -e "${YELLOW}Usage: ./find_subdomains.sh [options]${NC}"
    echo
    echo "   -f <file_name>             Optional, specifies file containing Top Level Domains. By default 'domains.txt' will be used."
    echo "   -d <domain_name>             Optional, specifies the domain to apply the scan on. If present, -f option will be ignored"
    echo
    echo -e "${YELLOW}Tools:${NC}"
    echo -e "   -A                         Run ${LIGHT_G}Amass${NC} tool."
    echo -e "   -aF                        Run ${LIGHT_G}AssetFinder${NC} tool."
    echo -e "   -sF                        Run ${LIGHT_G}SubFinder${NC} tool."
    echo -e "   -O                         Run ${LIGHT_G}OneForAll${NC} tool."
    echo -e "   -all                       Run ${LIGHT_G}all of the above${NC} tools."

    # echo some stuff here for the -a or --add-options 
    exit 1
}
#################################################################################


# Measuirng runtime
start=$(date +%s)

tools="AssetFinder"
domain_text="domains.txt"
domain_selected=""

if [ $# -eq 0 ]
then
    echo -e "${YELLOW}Usage: ./find_subdomains.sh [options]${NC}"
    echo
    echo "   -h, --help                 Display help text"
    exit
fi

for arg_n in $@
do
	case "$arg_n" in
		--help | -h)
			display_help
            exit
			;;
        -f)
			domain_text=$2
			;;
        -d)
			domain_selected=$2
			;;
		-A)
            if [[ "$tools" != *"Amass"* ]]; then
                tools+=" Amass"
            fi
			;;
	    -aF)
            if [[ "$tools" != *"AssetFinder"* ]]; then
                tools+=" AssetFinder";
            fi
			;;
	    -sF)
            if [[ "$tools" != *"SubFinder"* ]]; then
                tools+=" SubFinder"
            fi
			;;
        -O)
            if [[ "$tools" != *"OneForAll"* ]]; then
                tools+=" OneForAll"
            fi
			;;
        -all)
            tools="AssetFinder SubFinder Amass"
            ;;
    esac
done

if [ ! -d $PATH_RES/$domain_selected ]
then
    mkdir -p $PATH_RES/$domain_selected

    for tool in $tools; do
        $tool $domain_selected &
    done
    wait

    echo -e "[${LIGHT_B}INFO${NC}] Removing duplicates..."
    cat $PATH_RES/$domain_selected/subdomains_*.txt | sort -u > $PATH_RES/$domain_selected/subdomains.txt

else
    for tool in $tools; do
        $tool $domain_selected &
    done
    wait

    echo -e "[${LIGHT_B}INFO${NC}] Removing duplicates..."
    cat $PATH_RES/$domain_selected/subdomains_*.txt | sort -u > $PATH_RES/$domain_selected/subdomains_tmp.txt
    cat $PATH_RES/$domain_selected/subdomains_tmp.txt | anew $PATH_RES/$domain_selected/subdomains.txt &> /dev/null;
    rm -rf $PATH_RES/$domain_selected/subdomains_tmp.txt
fi

mkdir -p $PATH_RES/$domain_selected/old_subdomains
mv $PATH_RES/$domain_selected/subdomains_*.txt $PATH_RES/$domain_selected/old_subdomains

echo -e "[${LIGHT_G}OK${NC}] Found ${RED}$(wc -l $PATH_RES/$domain_selected/subdomains.txt | awk {'print $1'})${NC} subdomains."

end=$(date +%s)

echo -e "[${LIGHT_G}OK${NC}] Execution time: ${RED}$(($end - $start))${NC} seconds."

