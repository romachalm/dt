#!/bin/bash

# Need as input csv fle with "app, url"

##############################################################################
DEBUG=0
TSM_UPDATE=1

##############################################################################
# FUNCTIONAL VARIABLE
##############################################################################
EXPIRATION_LIMIT=45				# in days
SELF_PATH=$(pwd -P)	                        # find where the script is executed from
DATE=$( date +"%Y-%m-%d %H:%M:%S" )		# date formating
SILENT="-s"					# silent option used for curl
CACERT="cacert.pem"				# certificate file name
servername=$(hostname)                          # get server name  

##############################################################################
# Script parameters
##############################################################################
##############################################################################
# HELP
##############################################################################
##############################################################################
# Check command line arguments
##############################################################################
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*
# PREREQUISIT
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*
##############################################################################
# Function check dependencies
##############################################################################
function check_dependencies()
{
        FILE=$1
        if [ ${DEBUG} -eq 1  ] ; then echo -e "Test FILE: ${FILE}" ; fi
        if [[ ! -e ${FILE} ]]
        then
                echo -e "file ${FILE} must be present"
                exit
        else
                 if [ ${DEBUG} -eq 1  ] ; then echo -e "file ${FILE} present" ; fi
        fi
}
##############################################################################
# Test if cacert.pem files are present or need to be updated
##############################################################################
if [ ${DEBUG} -eq 1  ] ; then echo -e "Test if ${SELF_PATH}/${CACERT} is present" ; fi
if [[ ! -e ${SELF_PATH}/${CACERT} ]]
then
        echo -e "${SELF_PATH}/${CACERT} file not found ... downloading it"
        curl ${SILENT} --output ${SELF_PATH}/${CACERT} https://curl.haxx.se/ca/cacert.pem
else
	if [ ${DEBUG} -eq 1  ] ; then echo -e "File ${SELF_PATH}/${CACERT} exist" ; fi
	if [ ${DEBUG} -eq 1  ] ; then echo -e "Update ${SELF_PATH}/${CACERT} if needed" ; SILENT="" ; fi
	# Download if newer version of cacert.pem available
	curl ${SILENT} --time-cond ${SELF_PATH}/${CACERT} --output ${SELF_PATH}/${CACERT} https://curl.haxx.se/ca/cacert.pem
fi
##############################################################################
# Check dependencies
##############################################################################
for FILES in "${SELF_PATH}/${CACERT}" "${SELF_PATH}/api.sh"
do
	if [ ${DEBUG} -eq 1  ] ; then echo -e "File to be tested: ${FILES}" ; fi
	check_dependencies ${FILES}
done
##############################################################################
# Load external lib
##############################################################################
source ${SELF_PATH}/api.sh
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*
# FUNCTION
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*
##############################################################################
# Return code SSL certificate
##############################################################################
function ssl_return_code()
{
	URL=$1
	
	echo | openssl s_client -servername ${URL} -connect ${URL}:443 -CAfile cacert.pem 2>/dev/null | grep "Verify return code:" | awk -F\( '{print $2}' | tr -d ')'
}
##############################################################################
# expiration date
##############################################################################
function expiration_date()
{
	URL=$1
	EXPIRATION_DATE=$( echo | openssl s_client -servername ${URL} -connect ${URL}:443 2>/dev/null |  openssl x509 -enddate -noout | awk -F= '{print $2}' )
	echo $( date -ud "${EXPIRATION_DATE}" +'%F')
}
##############################################################################
# Expiration alert
##############################################################################
function expiration_alert()
{
	URL=$1
	
	EXPIRATION_LIMIT=$2	;	if [ ${DEBUG} -eq 1  ] ; then echo -e "EXPIRATION_LIMIT: ${EXPIRATION_LIMIT}" ; fi
	EXPIRATION_LIMIT_SEC=( ${EXPIRATION_LIMIT} * 86400 )
	EXPIRATION_RESULT=$( openssl s_client -servername ${URL} -connect ${URL}:443 < /dev/null 2>/dev/null | openssl x509 -checkend ${EXPIRATION_LIMIT_SEC} )
	EXPIRATION_ALERT=$?
	echo -e "EXPIRATION_ALERT: ${EXPIRATION_ALERT}"
}
##############################################################################
# Alert if expiration date is less than  days
##############################################################################
function alert_expiration()
{
	EXPIRATION_DATE=$1
	if [ ${DEBUG} -eq 1  ] ; then echo -e "EXPIRATION_DATE: ${EXPIRATION_DATE}" ; fi
	EXPIRATION_LIMIT=$2
	if [ ${DEBUG} -eq 1  ] ; then echo -e "EXPIRATION_LIMIT: ${EXPIRATION_LIMIT}" ; fi
	EXPIRATION_DATE_EPOCH=$( date -ud "${EXPIRATION_DATE}" +'%s' )
	CURENT_EPOCH=$( date +%s )
	DELTA_EPOCH=$(( ${EXPIRATION_DATE_EPOCH}-${CURENT_EPOCH}))
	DELTA_DAYS=$(( ${DELTA_EPOCH} / 86400 ))
	if [[ ${DELTA_DAYS} -gt ${EXPIRATION_LIMIT} ]]
	then
		echo -e "OK"
	else
		echo -e "Expire in less than ${EXPIRATION_LIMIT}" days
	fi
}
##############################################################################
# SSL certificate serial number extract
##############################################################################
function serial_number()
{
	URL=$1
	SERIAL_NUMBER=$( echo | openssl s_client -servername ${URL} -connect ${URL}:443 2>/dev/null |  openssl x509 -serial -noout | awk -F= '{print $2}' )
	echo -e "${SERIAL_NUMBER}"
}
##############################################################################
# IP resolution
##############################################################################
function ip_resolution()
{
	URL=$1
	IP=$( dig +short ${URL} )
	
	echo -e "${IP}"
}
##############################################################################
# IP localisation
##############################################################################
function ip_localisation()
{
	IP_SEARCH=$1
	IP_LOCALISATION=$( curl freegeoip.net/csv/${IP_SEARCH} 2>/dev/null | awk -F, '{print $3}' )
	echo -e "${IP_LOCALISATION}"
}
##############################################################################
# Alternative names extract
##############################################################################
function alternative_name()
{
	URL=$1
	ALTERNATIVE_NAME=$( echo | openssl s_client -servername ${URL} -connect ${URL}:443 2>/dev/null | openssl x509 -text | grep -A1 "Subject Alternative Name:" | tail -n +2 | tr -d 'DNS:' | tr -d ',' | sed 's/^ *//' )
	echo -e "${ALTERNATIVE_NAME}"
}
##############################################################################
# Read file in param and load it in an array
##############################################################################
function get_array()
{
	ARRAY=()
	while IFS= read -r line
	do
		ARRAY+=("$line")
	done < "$1"
}
##############################################################################
# Return code HTTP
##############################################################################
function http_status_code()
{
	URL=$1
	HTTP_STATUS_CODE=$( curl -k -s -o /dev/null -w "%{http_code}" https://${URL} )
	echo -e "${HTTP_STATUS_CODE}"
}
##############################################################################
#  httpd time out
#
#  Output of the function:
#  0 curl not in time out
#  1 curl timed out
##############################################################################
function httpd_timeout()
{
	if [[ ${DEBUG} -eq "1" ]] ; then echo -e "enter httpd_timeout function" ; fi
	URL=$1
	
	curl --connect-timeout 5 -k -s -o /dev/null https://${URL} > /dev/null 2>&1
	CURL_EXIT_CODE=$?
	if [[ ${DEBUG} -eq "1" ]] ; then echo -e "CURL_EXIT_CODE: ${CURL_EXIT_CODE}" ; fi
	CURL_TIME_OUT="0"
	if [[ ${CURL_EXIT_CODE} -eq "28" ]]
	then
		 CURL_TIME_OUT="1"
	fi
	if [[ ${DEBUG} -eq "1" ]] ; then echo -e "exit httpd_timeout function" ; fi
	echo ${CURL_TIME_OUT}
}
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*
# MAIN
#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*
# Download file from TSM
read_file 99 "url.csv" "${SELF_PATH}/url.csv"
# Test if file is present.
check_dependencies "${SELF_PATH}/url.csv"
# Load file
get_array "${SELF_PATH}/url.csv"
#################################
# Print table's head
#################################
echo -e "Alert,Application,Domain name,http code,IP,Location,Alternative names,Serial number,SSL Validity (YYYY-MM-DD),Authority" | tee ${SELF_PATH}/dtc_report.csv
# Loop to go through url to be tested
for APP_DOMAIN_NAME in "${ARRAY[@]}"
#for APP_DOMAIN_NAME in "test,training.analytics.msdialog.com" "test,ehr.easypodconnect2.com" "test,integ1.easypodconnect2.com" "test,preval1.easypodconnect2.com" "test,staging.msdialog.com" "test,train.msdialog.com"
#for APP_DOMAIN_NAME in "test,dev-docker.utility.valapp.com" "test,docker.utility.valapp.com" "test,bsm.dev-docker.utility.valapp.com" "test,bsm.docker.utility.valapp.com" 
do
	if [[ ${DEBUG} -eq 1 ]] ; then echo -e "\nAPP_DOMAIN_NAME: ${APP_DOMAIN_NAME}" ; fi
	if [[ ${APP_DOMAIN_NAME} =~ ^\#.* ]] || [[ -z ${APP_DOMAIN_NAME} ]]
	then
		if [[ ${DEBUG} -eq 1 ]] ; then echo "not processed,${APP_DOMAIN_NAME}" ; fi
	else
		if [[ ${DEBUG} -eq 1 ]] ; then echo -e "APP_DOMAIN_NAME: ${APP_DOMAIN_NAME}" ; fi
		# Extract application name
		APP=$( echo ${APP_DOMAIN_NAME} | awk -F, '{print $1}' ) ;			if [[ ${DEBUG} -eq 1 ]] ; then echo -e "APP: ${APP}" ; fi
		# extract domain name to be tested
		DOMAIN_NAME=$( echo ${APP_DOMAIN_NAME} | awk -F, '{print $2}' ) ;		if [[ ${DEBUG} -eq 1 ]] ; then echo -e "DOMAIN_NAME: ${DOMAIN_NAME}" ; fi
		# Test DNS registration
		IP=$( ip_resolution ${DOMAIN_NAME} ) ;                                          if [[ ${DEBUG} -eq 1 ]] ; then echo -e "IP: ${IP}" ; fi
		if [[ -z ${IP} ]]
		then
			if [[ ${DEBUG} -eq 1 ]] ; then echo -e "No DNS registration" ; fi
		
			echo -e "no DNS entry,${APP},${DOMAIN_NAME},N/A,N/A,N/A,N/A,N/A,N/A,N/A" | tee -a ${SELF_PATH}/dtc_report.csv
			continue
		fi
		# Test httpd timeout
		HTTPD_TIMEOUT=$( httpd_timeout ${DOMAIN_NAME} ) ;				if [[ ${DEBUG} -eq 1 ]] ; then echo -e "HTTPD_TIMEOUT: ${HTTPD_TIMEOUT}" ; fi
		if [[ ${HTTPD_TIMEOUT} -ne 0 ]]
		then
			echo -e "curl timeout limit exceeded,${APP},${DOMAIN_NAME},N/A,${IP},N/A,N/A,N/A,N/A,N/A" | tee -a ${SELF_PATH}/dtc_report.csv
			continue
		fi
		# Information retrieval
		HTTP_STATUS_CODE=$( http_status_code ${DOMAIN_NAME} ) ;				if [[ ${DEBUG} -eq 1 ]] ; then echo -e "HTTP_STATUS_CODE: ${HTTP_STATUS_CODE}" ; fi
		if [[ -z ${HTTP_STATUS_CODE} ]] ; then HTTP_STATUS_CODE="N/A" ; fi
		SSL_VALIDITY_DATE=$( expiration_date ${DOMAIN_NAME} ) ;				if [[ ${DEBUG} -eq 1 ]] ; then echo -e "SSL_VALIDITY_DATE: ${SSL_VALIDITY_DATE}" ; fi
		if [[ -z ${SSL_VALIDITY_DATE} ]] ; then SSL_VALIDITY_DATE="N/A" ; fi
		ALERT=$( alert_expiration ${SSL_VALIDITY_DATE} ${EXPIRATION_LIMIT} ) ;		if [[ ${DEBUG} -eq 1 ]] ; then echo -e "ALERT: ${ALERT}" ; fi
		if [[ -z ${ALERT} ]] ; then ALERT="N/A" ; fi
		EXPIRATION_DATE=$( expiration_date ${DOMAIN_NAME} ) ;				if [[ ${DEBUG} -eq 1 ]] ; then echo -e "EXPIRATION_DATE: ${EXPIRATION_DATE}" ; fi
		if [[ -z ${EXPIRATION_DATE} ]] ; then EXPIRATION_DATE="N/A" ; fi
		IP=$( ip_resolution ${DOMAIN_NAME} ) ;						if [[ ${DEBUG} -eq 1 ]] ; then echo -e "IP: ${IP}" ; fi
		if [[ -z ${IP} ]] ; then IP="N/A" ; fi
		IP_LOCALISATION=$( ip_localisation ${IP} ) ;					if [[ ${DEBUG} -eq 1 ]] ; then echo -e "IP_LOCALISATION: ${IP_LOCALISATION}" ; fi
		if [[ -z ${IP_LOCALISATION} ]] ; then IP_LOCALISATION="N/A" ; fi
		ALTERNATIVE_NAME=$( alternative_name ${DOMAIN_NAME} ) ;				if [[ ${DEBUG} -eq 1 ]] ; then echo -e "ALTERNATIVE_NAME: ${ALTERNATIVE_NAME}" ; fi
		if [[ -z ${ALTERNATIVE_NAME} ]] ; then ALTERNATIVE_NAME="N/A" ; fi
		SERIAL_NUMBER=$( serial_number ${DOMAIN_NAME} ) ;				if [[ ${DEBUG} -eq 1 ]] ; then echo -e "SERIAL_NUMBER: ${SERIAL_NUMBER}" ; fi
		if [[ -z ${SERIAL_NUMBER} ]] ; then SERIAL_NUMBER="N/A" ; fi
		SSL_CODE_RETURN=$( ssl_return_code ${DOMAIN_NAME} ) ;				if [[ ${DEBUG} -eq 1 ]] ; then echo -e "SSL_CODE_RETURN: ${SSL_CODE_RETURN}" ; fi
		if [[ -z ${SSL_CODE_RETURN} ]] ; then SSL_CODE_RETURN="N/A" ; fi
		
		# Information presentation /!\ Update Table's head if you change this line /!\
		echo -e "${ALERT},${APP},${DOMAIN_NAME},${HTTP_STATUS_CODE},${IP},${IP_LOCALISATION},${ALTERNATIVE_NAME},${SERIAL_NUMBER},${SSL_VALIDITY_DATE},${SSL_CODE_RETURN}" | tee -a ${SELF_PATH}/dtc_report.csv
	fi
done
# Test if file is present.
check_dependencies "${SELF_PATH}/dtc_report.csv"
# Commit file to tsm
if [[ TSM_UPDATE -eq 1 ]]
then
	commit_file 103 "${SELF_PATH}/dtc_report.csv" "DTC Report - ${DATE}"
fi
rm -f ${SELF_PATH}/dtc_report.csv
exit