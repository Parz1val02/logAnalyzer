#!/bin/bash
#Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

#Catch the sigkill signal when it is send to end with CTRL-C to kill the program
trap ctrl_c INT
function ctrl_c(){
    echo -e "\n${redColour}[!] Exiting program...\n${endColour}"
    rm *.at 2>/dev/null
    tput cnorm; exit 1
}
#Help function when the program has not been executed correctly
function helpPanel(){
	echo -e "\n${greenColour}This script analyzes compressed log archives (*.tar.gz) from any exposed service for ip addresses from potential attackers${endColour}"
    echo -e "\n${redColour}[!] Usage: $0${endColour}\n"
    for i in $(seq 1 80); do echo -ne "${redColour}-"; done; echo -ne "${endColour}"
    echo -e "\n\n${grayColour}[-a]${endColour}${yellowColour} Analysis mode${endColour}"
    echo -e "\t${purpleColour}ips${endColour}${yellowColour}:\t List information about the ip addresses found${endColour}\n"
    echo -e "${grayColour}[-n]${endColour}${yellowColour}:Limit the number of results${endColour}${blueColour} (Example: -n 10)${endColour}\n"
	echo -e "${grayColour}[-l}${endColour}${yellowColour}:Specify the compressed log archive to analyze${endColour}${blueColour} (Example: -l archive.tar.gz)${endColour}\n"
    echo -e "${grayColour}[-h]${endColour}${yellowColour}:Invoke this help panel${endColour}\n"
    tput cnorm; exit 1;
}

function dependencies(){
	tput civis
	local program=7z	
	if [ ! "$(command -v $program)" ]; then
		echo -e "${redColour}[X]${endColour}${grayColour} $program${endColour}${yellowColour} is not installed in your system${endColour}\n"; sleep 1
    	echo -e "${redColour}[!] Exiting program...\n${endColour}"
    	rm *.at 2>/dev/null
    	tput cnorm; exit 1
	fi
}

#Functions to dynamically create tables
function printTable(){

    local -r delimiter="${1}"
    local -r data="$(removeEmptyLines "${2}")"

    if [[ "${delimiter}" != '' && "$(isEmptyString "${data}")" = 'false' ]]
    then
        local -r numberOfLines="$(wc -l <<< "${data}")"

        if [[ "${numberOfLines}" -gt '0' ]]
        then
            local table=''
            local i=1

            for ((i = 1; i <= "${numberOfLines}"; i = i + 1))
            do
                local line=''
                line="$(sed "${i}q;d" <<< "${data}")"

                local numberOfColumns='0'
                numberOfColumns="$(awk -F "${delimiter}" '{print NF}' <<< "${line}")"

                if [[ "${i}" -eq '1' ]]
                then
                    table="${table}$(printf '%s#+' "$(repeatString '#+' "${numberOfColumns}")")"
                fi

                table="${table}\n"

                local j=1

                for ((j = 1; j <= "${numberOfColumns}"; j = j + 1))
                do
                    table="${table}$(printf '#| %s' "$(cut -d "${delimiter}" -f "${j}" <<< "${line}")")"
                done

                table="${table}#|\n"

                if [[ "${i}" -eq '1' ]] || [[ "${numberOfLines}" -gt '1' && "${i}" -eq "${numberOfLines}" ]]
                then
                    table="${table}$(printf '%s#+' "$(repeatString '#+' "${numberOfColumns}")")"
                fi
            done

            if [[ "$(isEmptyString "${table}")" = 'false' ]]
            then
                echo -e "${table}" | column -s '#' -t | awk '/^\+/{gsub(" ", "-", $0)}1'
            fi
        fi
    fi
}

function removeEmptyLines(){

    local -r content="${1}"
    echo -e "${content}" | sed '/^\s*$/d'
}

function repeatString(){

    local -r string="${1}"
    local -r numberToRepeat="${2}"

    if [[ "${string}" != '' && "${numberToRepeat}" =~ ^[1-9][0-9]*$ ]]
    then
        local -r result="$(printf "%${numberToRepeat}s")"
        echo -e "${result// /${string}}"
    fi
}

function isEmptyString(){

    local -r string="${1}"

    if [[ "$(trimString "${string}")" = '' ]]
    then
        echo 'true' && return 0
    fi

    echo 'false' && return 1
}

function trimString(){

    local -r string="${1}"
    sed 's,^[[:blank:]]*,,' <<< "${string}" | sed 's,[[:blank:]]*$,,'
}

#Function to analyze the log compressed archive for ip addresses
function archive_analysis(){
	local log_archive=$1
	local number=$2
	local name_d=$(7z l $log_archive | grep "Name" -A 2 | tail -n 1 | awk 'NF{print $NF}')
	7z x $log_archive > /dev/null 2>&1
	logs=($(7z l $name_d | grep "Name" -A 20 | grep "files" -B 20 | grep -Ev "Name|files" | awk 'NF{print $NF}' | grep -v "-"))
	7z x $name_d > /dev/null 2>&1
	rm $name_d >/dev/null 2>&1
	for i in ${!logs[@]};do
		file=${logs[${i}]}
		7z l $file >/dev/null 2>&1
     	if [ "$(echo $?)" == "0" ]; then
         	logs[${i}]=$(7z l $file | grep "Name" -A 2 | tail -n 1 | awk 'NF{print$NF}')
         	7z x $file >/dev/null 2>&1 
			rm $file >/dev/null 2>&1
		fi
	done

	for file in ${logs[@]}; do
		cat $file | grep -o "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}" | sort | uniq -c | sort -nr >> attackers.at	
		rm $file >/dev/null 2>&1
	done
	cat attackers.at | sort -nr | uniq >> attackersv2.at
	cat attackersv2.at | awk '{print $2}' | sort | uniq >> attackersv3.at
	awk '{print NR " " $1}' attackersv3.at >> attackersv4.at
	local number_ips=$(cat attackersv4.at | wc -l)	
	
	until [ $number -eq 0 ]; do
		line=$(echo $((1 + $RANDOM % $number_ips)))	
		grep "^$line " attackersv4.at | awk 'NF{print $NF}' >> ips	
		number=$(expr $number - 1)
	done
	
	echo "IP Address_City_Region_Country_Latitude_Longitude" > table.at
	while read ip;do
		curl -s ipinfo.io/$ip > info.at	
		echo "${ip}_$(cat info.at | grep city | awk 'BEGIN{FS="\""} {print $(NF-1)}')_$(cat info.at | grep region | awk 'BEGIN{FS="\""} {print $(NF-1)}')_$(cat info.at | grep country | awk 'BEGIN{FS="\""} {print $(NF-1)}')_$(cat info.at | grep loc | awk 'BEGIN{FS="\""} {print $(NF-1)}' | tr "," " " | awk '{print $1}')_$(cat info.at | grep loc | awk 'BEGIN{FS="\""} {print $(NF-1)}' | tr "," " " | awk '{print $2}')" >> table.at
	done < ips
	
	rm ips 
	if [ "$(cat table.at | wc -l)" != "1" ]; then
        echo -ne "${greenColour}"
        printTable '_' "$(cat table.at)"
        echo -ne "${endColour}"
        tput cnorm; rm *.at >/dev/null 2>&1
		exit 0
    else
        tput cnorm; rm *.at >/dev/null 2>&1
		exit 1
    fi
} 

#Main program execution
dependencies; parameter_counter=0; while getopts "a:n:l:h:" arg; do
	case $arg in
		a)analysis_mode=$OPTARG; let parameter_counter+=1;;
		n)number_output=$OPTARG; let parameter_counter+=1;;
		l)log_archive=$OPTARG; let parameter_counter+=1;;
		h)helpPanel;;
	esac
done

tput civis

#Conditional that will evaluate whether the program has been correctly executed or send the user to the help panel
if [ "$parameter_counter" -eq 0 ];then
	helpPanel
else
	if [ "$(echo $analysis_mode)" == "ips" ];then
		if [ ! "$log_archive" ];then
    	echo -e "\n${redColour}[!] No compressed log archive was specified...\n${endColour}"
    	echo -e "\n${redColour}[!] Exiting program...\n${endColour}"
    	tput cnorm; exit 1
		fi
		if [ ! "$number_output" ];then
			number_output=25
		fi
		archive_analysis $log_archive $number_output	
	fi
fi
