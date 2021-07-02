#!/bin/bash

# replace mycompany with correct company or host name. check all 8 places. 

# Global Variables

# modes of operation
DEBUG=0
INTERACTIVE=0
TEST=0

# user credentials
USERNAME=""   # domain login ID
PASSWORD=""   # domain login password

# Identify platform type
# 'Darwin' assumed to be MacOS
uname=$(uname -s) 

# assumed command defaults: Linux
cmd_sed='sed'
cmd_base64='base64 -d'

# setting identity provider URIs
uri_mycompany_okta="https://mycompany.okta.com"
uri_okta_authentication="$uri_mycompany_okta/api/v1/authn"
uri_okta_sessions="$uri_mycompany_okta/api/v1/sessions"
uri_okta_applinks="$uri_mycompany_okta/api/v1/users/me/appLinks"
uri_okta_metadata=""

SAMLResponse=""

stateToken=""     # state token derived from ... some random thing
sessionToken=""   # session token derived from stateToken
sessionCookie=""  # session cookie derived from sessionToken

declare -a factorType       # Multi-factor type
declare -a factorID         # Multi-factor ID
declare -a providerName     # Multi-factor provider name
declare -a verifyURI        # Multi-factor URI

declare -a app_id           # application ID
declare -a app_label        # application label or description
declare -a app_linkurl      # application link URL
declare -a app_instanceID   # applicaiton instance ID
declare -a app_assignmentID # application assignment ID
appCount=0                  # number of discovered applications
roleCount=0                 # number of discovered roles

# default aws profile configuration attributes
aws_profile_name='default'
aws_access_key_id=''
aws_secret_access_key=''
aws_profile_region='us-east-1'
aws_profile_output='json'

# colors
red=$'\e[1;31m'
grn=$'\e[1;32m'
yel=$'\e[1;33m'
blu=$'\e[1;34m'
mag=$'\e[1;35m'
cyn=$'\e[1;36m'
end=$'\e[0m'


# command line argument options
usage() {
cat <<EOF
Shell script to authenticate against Okta API.

  Options:
  -d     Show debugging information      
  -h     This help message
  -i     Interactive mode

  Usage:
    Show help file.
    $0 -h
    
    Debug interactive mode. 
    $0 -d -i

EOF
}


# returns TRUE "1" if digit, FALSE "0" on anything else
isDigit() {
  # return false if insufficient numbers
  if [ $# -lt 1 ]; then
    #printf "insufficient\n"
    return 0
  fi

  # return false if not a number
  if [[ ! ("$1" =~ ^[0-9]+$) ]]; then
    #printf "not number\n"
    return 0
  fi

  # return true if all tests pass
  #printf "success\n"
  return 1
}


# identifies platform due to differences between macOS (bsd) and unix (gnu)
identify_platform() {
  
  # if MacOS, change the commands used
  if [ $uname = "Darwin" ]; then
    cmd_sed="gsed"
    cmd_base64='base64 -D'
  fi

}


# check to ensure all dependencies available
check_dependencies() {
  #if [ "$DEBUG" -eq 1 ]; then
    printf "Checking dependencies....\n"
  #fi

  local exitCode=''
  local dependencies=1 # assume all dependencies available

  # set platform specific variables
  identify_platform

  # curl test
  type curl > /dev/null 2>&1
  exitCode=$? # capture exit code from last command

  if [ "$exitCode" -ne 0 ]; then
    printf "  ${red}'curl' not found! (cli web browser)\n${end}"
    dependencies=0
  else
    if [ "$DEBUG" -eq 1 ]; then
      printf "  ${grn}'curl' found!\n${end}"
    fi
  fi


  # jq test
  type jq > /dev/null 2>&1
  exitCode=$?   

  if [ "$exitCode" -ne 0 ]; then
    printf "  ${red}'jq' not found! (json parser)\n${end}"
    printf "    MacOS Installation:  https://jira.mycompany.com:8444/display/CLOUD/Configure+PowerShell+for+AWS+Automation#ConfigurePowerShellforAWSAutomation-MacOSSetupforBashScript\n"
    printf "    Ubuntu Installation: sudo apt install jq\n"
    printf "    Redhat Installation: sudo yum install jq\n"
    dependencies=0
  else
    if [ "$DEBUG" -eq 1 ]; then
      printf "  ${grn}'jq' found!\n${end}"
    fi
  fi


  # sed/gsed test
  if [ $uname = "Darwin" ]; then
    type gsed > /dev/null 2>&1
    exitCode=$? 
  else
    type sed > /dev/null 2>&1
    exitCode=$? 
  fi

  if [ "$exitCode" -ne 0 ]; then
    printf "  ${red}'%s' not found! (stream editor)\n${end}" $cmd_sed
    dependencies=0
  else
    if [ "$DEBUG" -eq 1 ]; then
      printf "  ${grn}'%s' found!\n${end}" $cmd_sed
    fi
  fi


  # base64 test
  type base64 > /dev/null 2>&1
  exitCode=$? 

  if [ $exitCode -ne 0 ]; then
    printf "  ${red}'base64' not found! (base64 d/encoder)\n${end}" 
    dependencies=0
  else
    if [ "$DEBUG" -eq 1 ]; then
      printf "  ${grn}'base64' found!\n${end}" 
    fi
  fi

  
  # aws test
  type aws > /dev/null 2>&1
  exitCode=$? 
  
  if [ $exitCode -ne 0 ]; then
    printf "  ${red}'aws' not found! (aws cli)\n${end}" 
    dependencies=0
  else
    if [ "$DEBUG" -eq 1 ]; then
      printf "  ${grn}'aws' found!\n${end}" 
    fi
  fi
  

  if [ $dependencies -eq 0 ]; then
    printf "${red}Missing dependencies, exiting.\n${end}"
    exit 1
  fi

}


# input: domain username and password
# note: always read password with -s parameter to avoid capturing password value in plain text
prompt_user_credentials() {
  printf "Enter domain credentials...\n"

  read -p "  Enter Username: " USERNAME
  read -s -p "  Enter Password: " PASSWORD

  printf "\n"
}


# authenticate user credentials against Okta API
# Input: USERNAME and PASSWORD are sent to uri_okta_authentication
# Result: curlResult and oktaStatus (due to MFA)
curl_okta_auth() {
  local oktaStatus=""

  # Authenticate to Okta using Domain username and password.
  printf "Authenticating against Okta as ${USERNAME}...\n"

  IFS=$'\n'
  curlResult=`curl -s -X POST \
  ${uri_okta_authentication} \
  -H 'accept: application/json' \
  -H 'cache-control: no-cache' \
  -H 'content-type: application/json' \
  -d '{
  "username": "'${USERNAME}'",
  "password": "'${PASSWORD}'"}'`

  if [ "$DEBUG" -eq 1 ]; then
    printf "\n%s() response: \n%s\n" ${FUNCNAME[0]} $curlResult
  fi

  # Authentication Error Checking
  errorSummary=''
  errorSummary=(`echo $curlResult | jq '.errorSummary'`)
  if [ "$errorSummary" != "null" ]; then
    printf "  ${red}Error: %s\n ${end}" $errorSummary
    exit 1;
  fi

  oktaStatus=(`echo $curlResult | jq -r '.status'`)
  if [ "${oktaStatus}" != "MFA_REQUIRED" ]; then
    printf "${yel}Warning: MFA is not required, exiting\n${end}"
    exit 1;
  fi

  printf "   ${grn}Success${end} \n\n"
}


# parse through the MFA options returned from successful authentication to Okta
# Input: curlResult from successful Okta API authentication call.
# Result: Okta stateToken, factorType, id, provider, and _link.verify.href
parse_mfa_options() {
  # Authentication Response Parsing
  stateToken=(`echo $curlResult | jq -r '.stateToken'`)   
  factorType=(`echo $curlResult | jq -r '._embedded.factors[] | .factorType'`)
  factorID=(`echo $curlResult | jq -r '._embedded.factors[] | .id'`)
  providerName=(`echo $curlResult | jq -r '._embedded.factors[] | .provider'`)
  verifyURI=(`echo $curlResult | jq -r '._embedded.factors[] | ._links.verify.href'`)
}


# generate a list of MFA options (i.e. SMS, Yubikey, Google Authenticator, Okta Verify, etc.)
# Input: factorType & factorCount from successful Okta API authentication call.
# Result: Okta list of MFA options for the user to select.
show_mfa_options() {
  # get the factorCount of the array (number of elements)
  local factorCount=${#factorType[@]}
  
  echo "MFA options available: $factorCount"

  # Display MFA authentication options
  for ((n=0; n<$factorCount; ++n)) do
    printf "  [%d] %-8s %-20s" $n ${providerName[$n]} ${factorType[$n]} 
      if [ "$DEBUG" -eq 1 ]; then
        printf "  [%s] %s" ${factorID[$n]} ${verifyURI[$n]}
      fi
    printf "\n"
  done
}


# accept mfa selection from user and process authentication against Okta
process_mfa_option() {
  # get the factorCount of the array (number of elements)
  local factorCount=${#factorType[@]}
  local selection=''
  local exitCode=''

  if [ "$factorCount" -eq 1 ]; then
    selection=0
  else 
    selection=''
  fi
  
  #while [ "$selection" -lt 0 ]; do
  while [ -z $selection ]; do
    read -p "Your selection? " selection
    
    isDigit $selection
    exitCode=$?

    # if digit TRUE
    if [ "$exitCode" -eq 1 ]; then
      # if digit within range
      if [[ "$selection" -ge 0 && "$selection" -lt "$factorCount" ]]; then 
        break
      fi
    fi
    selection=''
  done

  # initiate a one-time token from a mobile device or application
  if [ ${providerName[$selection]} == "OKTA" ]; then
    if [[ ${factorType[$selection]} == "sms" || ${factorType[$selection]} == "push" ]]; then
      printf "Notification initiated (push or sms)...\n"

      curlResult=`curl -s -X POST \
      ${verifyURI[$selection]} \
      -H 'accept: application/json' \
      -H 'cache-control: no-cache' \
      -H 'content-type: application/json' \
      -d '{
      "stateToken": "'${stateToken}'",
      "factorId": "'${factorID[$selection]}'"}'`

      if [ "$DEBUG" -eq 1 ]; then
        printf "\n%s() response: \n%s\n" ${FUNCNAME[0]} $curlResult
      fi
    fi
  fi

  local mfaSuccess=0
  while [ $mfaSuccess -eq 0 ]; do  
    # Prompt for MFA code from the user
    read -p "Enter your ${providerName[$selection]} code: " mfaPasscode
  
    # Verify MFA code against Okta
    # Note, there could be specific MFA options which require a custom data section.
    printf "\nVerifying MFA code...\n"
  
    
    curlResult=`curl -s -X POST \
    ${verifyURI[$selection]} \
    -H 'accept: application/json' \
    -H 'cache-control: no-cache' \
    -H 'content-type: application/json' \
    -d '{
    "stateToken": "'${stateToken}'",
    "passCode": "'${mfaPasscode}'"}'`
  
    # exit on verify failure
    IFS=$'\n'
    local errorSummary=(`echo $curlResult | jq '.errorSummary'`)
    if [ "$errorSummary" != "null" ]; then
      printf "  ${red}Error: %s\n\n${end}" $errorSummary
    else
      printf "   ${grn}Success${end} \n\n"
      mfaSuccess=1
    fi
  
    if [ "$DEBUG" -eq 1 ]; then
      printf "\n%s() response: \n%s\n" ${FUNCNAME[0]} $curlResult
    fi
  done
}


# take result from Okta Authentication (curlResult) and set the sessionToken variable
# Input: curlResult from successful Okta API authentication call.
# Result: Okta stateToken, factorType, id, provider, and _link.verify.href
set_sessionToken() {
  local expiry=''

  # FIXME: Apple Watch users not receiving a sessionToken.

  #printf "\nExtracting sessionToken...\n"
  sessionToken=(`echo $curlResult | jq -r '.sessionToken'`)    
  if [ "$sessionToken" == "null" ]; then
    printf "\nresponse: %s\n\n" $curlResult
    printf "${yel}Warning: sessionToken not found, exiting\n${end}"
    exit 1;
    fi
 
  IFS=$'\n'
  expiry=(`echo $curlResult | jq -r '.expiresAt'`)

  if [ "$DEBUG" -eq 1 ]; then
    printf "  sessionToken: %s\n" $sessionToken

    if [ $uname = "Darwin" ]; then
      # well, again, because MacOS...
      printf "    ${yel}sessionToken Expiration:${end} %s\n\n" $expiry
    else
      printf "    ${yel}sessionToken Expiration:${end} %s\n\n" `date -d"$expiry"`
    fi
  fi
}


# obtain a sessionID
# Input: url($1), token($2)
# Result: sessionCookie
curl_get_sessionID() {
  if [ $# -lt 2 ]; then
    printf "${red}Error in %s(): insufficient arguments (%d).\n${end}" ${FUNCNAME[0]} $# 
    exit 2
  fi

  local url=$1
  local token=$2

  curlResult=`curl -s -X POST $url \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"sessionToken": "'${token}'"}'`
  
  if [ "$DEBUG" -eq 1 ]; then
    printf "\n%s() response: \n%s\n" ${FUNCNAME[0]} $curlResult
  fi

  sessionID=(`echo $curlResult | jq -r '.id'`)
  sessionCookie="$(printf "sid=%s Domain=%s " $sessionID "mycompany.okta.com")"

  if [ "$DEBUG" -eq 1 ]; then
    printf "sessionCookie: %s\n" $sessionCookie
  fi

}


# obtain list of all of the Okta App links
# Input: uri_okta_applinks, sessionCookie
# Result: curlResult
curl_get_appLinks() {
  curlResult=`curl -s -X GET ${uri_okta_applinks} \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -H "Cookie: ${sessionCookie}"`

  if [ "$DEBUG" -eq 1 ]; then
    printf "\n%s() response: \n%s\n" ${FUNCNAME[0]} $curlResult
  fi

  parse_appLinks $curlResult
}


# Parse Okta application list, storing key values in relevant arrays.
# Input: curlResult from successful Okta API appLinks call.
# Result: key application values stored in five unique arrays
parse_appLinks() {
  if [ $# -lt 1 ]; then
    printf "${red}Error: parse_appList() insufficient arguments (%d).\n${end}" $# 
    exit 2
  fi

  # query of appName field in appLinks JSON result
  query="amazon_aws"

  # TODO: Consider user option to filter Okta apps by 'contains' jq query.
  # | jq -r '.[] | select(.label | contains ("AWS")) | .label'

  app_id=(`echo $curlResult | jq -r '.[] | select(.appName=="'$query'") | .id'`)
  app_label=(`echo $curlResult | jq -r '.[] | select(.appName=="'$query'") | .label'`)
  app_linkUrl=(`echo $curlResult | jq -r '.[] | select(.appName=="'$query'") | .linkUrl'`)
  app_instanceId=(`echo $curlResult | jq -r '.[] | select(.appName=="'$query'") | .appInstanceId'`)
  app_assignmentId=(`echo $curlResult | jq -r '.[] | select(.appName=="'$query'") | .appAssignmentId'`)

  # get the number apps listed
  appCount=${#app_label[@]}

  if [ "$DEBUG" -eq 1 ]; then
    printf "\nApps found: %s\n\n" $appCount
  fi
}


# Display all app labels
show_app_options() {
  printf "List of Apps: \n"

  for i in "${!app_label[@]}" 
    do
      printf "  [%d] %s\n" $i ${app_label[$i]}
    done
}


# user will select Okta app (AWS) they would like to access
# Input: response
# Result: sessionCookie
prompt_app_selection() {
  local selection=''
  local exitCode=''

  while [ -z $selection ]; do
    read -p "Your selection? " selection
    
    isDigit $selection
    exitCode=$?

    # if digit TRUE
    if [ "$exitCode" -eq 1 ]; then
      # if digit within range
      if [[ "$selection" -ge 0 && "$selection" -lt "$appCount" ]]; then 
        break
      fi
    fi
    selection=''
  done

  echo $selection
}


# obtain information about a specific application in Okta (e.g. multiple roles)
# Input: app_instanceId($1)
curl_get_appMetaDataURI() {
  if [ $# -lt 1 ]; then
    printf "${red}Error in %s(): insufficient arguments (%d).\n${end}" ${FUNCNAME[0]} $# 
    exit 2
  fi

  # well, because git-bash and parsing includes something unseen...
  local instanceID=`echo $1`

  IFS=$'' # desginate internal file separator as null
  
  curlResult=`curl -s -X GET ${uri_mycompany_okta}/api/v1/apps/${instanceID}/sso/saml/metadata \
    -H "Accept: application/xml" \
    -H "Content-Type: application/json" \
    -H "Cookie: ${sessionCookie}"`

  if [ "$DEBUG" -eq 1 ]; then
    printf "\n%s() response: \n%s\n%s\n" ${FUNCNAME[0]} $curlResult  $sessionCookie
  fi

  local search="<?xml"
  if [[ ! "$curlResult" =~ "$search" ]]; then
    printf "${red}Error in %s(): result is not XML\n${end}" ${FUNCNAME[0]}
    exit 1
 fi

  parse_appMetaDataURI $curlResult  
}


# expects xml documents as input
# writes result to $uri_okta_metadata
parse_appMetaDataURI() {
  if [ $# -lt 1 ]; then
    printf "${red}Error in %s(): insufficient arguments (%d).\n${end}" ${FUNCNAME[0]} $# 
    exit 2
  fi

  local curlResult=$1
  local temp=''
  
  # create newlines based on tag opening character '<''
  temp=`echo $curlResult | $cmd_sed 's/</\n</g'`
  
  # isolate only the line we are interested 'HTTP-POST'
  temp=`echo $temp | grep HTTP-POST`
  
  # get rid of everything from the beginning of the line to 1st quote of Location="
  temp=`echo $temp | $cmd_sed 's/^.*Location="//g'`

  # get rid of the trailing tag closing '"\>'
  temp=`echo $temp | $cmd_sed 's/"\/>//g'`

  uri_okta_metadata=$temp
  if [ "$DEBUG" -eq 1 ]; then
    printf "\nURI for Okta Metadata: %s\n\n" $uri_okta_metadata
  fi
}


# Display detail about a single identified Okta application.
# Input: integer
# Output: displays results to STDOUT
show_appDetail_byIndex() {
  if [ $# -lt 1 ]; then
    printf "${red}Error in %s(): insufficient arguments (%d).\n${end}" ${FUNCNAME[0]} $#  
    exit 2
  fi
  printf "Application Detail:\n"
  printf "          label: %s\n" ${app_label[$1]}
  printf "             id: %s\n" ${app_id[$1]}
  printf "        linkUrl: %s\n" ${app_linkUrl[$1]}
  printf "  appInstanceId: %s\n" ${app_instanceId[$1]}
  printf "appAssignmentId: %s\n" ${app_assignmentId[$1]}
  printf "\n"
}


# list of roles the user has access to with the selected app
# input: url($1), cookie($2)
# output: sessioncookie
curl_get_appRoles() {
  if [ $# -lt 2 ]; then
    printf "${red}Error in %s(): insufficient arguments (%d).\n${end}" ${FUNCNAME[0]} $# 
    exit 2
  fi

  local url=$1        # target url
  local cookie=$2     # session cookie
  local curlResult="" # results from curl
  local line=""       # place to put grep results
  local search="name=\"SAMLResponse\""

  curlResult=`curl -s -X GET $url \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -H "Cookie: ${cookie}"`

  if [ "$DEBUG" -eq 1 ]; then
    printf "\n%s() response: \n%s\n" ${FUNCNAME[0]} $curlResult
  fi

  line=`echo $curlResult | grep $search` 

  # make sure there was a match to the grep search
  if [ -z "$line" ]; then
    printf "${red}Error in %s(): \"%s\" is not found\n${end}" ${FUNCNAME[0]} $search
    exit 1
  fi

  parse_appRoles $line
}


# Extracts SAML application roles
# Expects as input the "SAMLResponse" HTML input tag
# Sets role_* global variables
parse_appRoles() {
  local input=$1         # base64 input
  local xml_data=""      # xml extracted from base64 decode
  local unicode_chars="" # storage of any missed unicode characters
  declare -a role_array  # an array to stick stuff
  declare -a line

  IFS=$'' # internal file separator

  # get rid of everything from the beginning of the line to 1st quote of '.*value="'
  input=`echo $input | $cmd_sed 's/^.*value\="//g'`

  # get rid of the trailing tag closing '"\>'
  input=`echo $input | $cmd_sed 's/"\/>//g'`

  # replace unicode hex character codes with actual characters
  # &#x2b; is  +
  # &#x3d; is  =
  # could be replaced with command 'recode'
  input=`echo $input | $cmd_sed 's/&#x2b;/+/g'`
  input=`echo $input | $cmd_sed 's/&#x3d;/=/g'`

  # test to see if unicode characters were missed.
  unicode_chars=`echo $input | egrep -o '&.{5}' | uniq -c` 
  if [ -n "$unicode_chars" ]; then
    printf "${red}Error in %s(): unaccounted for unicode characters\n%s\n${end}" ${FUNCNAME[0]} $unicode_chars
    exit 1;
  fi

  SAMLResponse=$input

  if [ "$DEBUG" -eq 1 ]; then
    printf "\nSAMLResponse: \n%s\n\n" $input
  fi

  # Because, well, MacOS uses -D and Linux uses -d
  # Have to do something to distinguish base64 versions
  # $ base64 --version | head -n 1
  # base64 (GNU coreutils) 8.25
  xml_data=`echo $input | eval $cmd_base64`

  # create newlines based on tag opening character '<''
  xml_data=`echo $xml_data | $cmd_sed 's/</\n</g'`
  
  # find lines that contain role in them
  xml_data=`echo $xml_data | grep ':role'`

  # get rid of everything from the beginning of the line to 1st quote of '.*xs:string=">'
  xml_data=`echo $xml_data | $cmd_sed 's/^.*xs:string">//g'`

  #printf "xml_data:\n%s\n\n" $xml_data

  # split single variable containing multiple lines into unique array elements
  IFS=$'\n '
  read -d '' -a role_array <<< "$xml_data"

  roleCount=${#role_array[@]}

  for i in "${!role_array[@]}" 
    do
      role_principal[$i]=`echo ${role_array[$i]} | $cmd_sed 's/,.*//g'`
      role_awsARN[$i]=`echo ${role_array[$i]} | $cmd_sed 's/^.*,//g'`
      role_label[$i]=`echo ${role_array[$i]} | $cmd_sed 's/^.*\///g'`
    done  
}


# display a list of roles the user has access to.
# input: index array
# output: role_label , role_principal, role_awsARN
show_app_roles() {
  printf "\n"

  printf "Role options available: %s\n" $roleCount
  for index in "${!role_label[@]}" 
    do
      printf "  [%d] %s\n"  $index ${role_label[$index]} 

      if [ "$DEBUG" -eq 1 ]; then
        printf "  principal: %s\n" ${role_principal[$index]}
        printf "        arn: %s\n" ${role_awsARN[$index]} 
      fi      
    done
}


# get user input on role selection
# Input: user selection (response)
# Result: response
prompt_role_selection() {
  local selection=''
  local exitCode=''

  # when only 1 role is assigned, the script will default to it and 
  # continue without user input otherwise ask for user input.
  if [ "$roleCount" -eq 1 ]; then
    #echo "Setting selection=0"
    selection=0
  else 
    #echo "Setting selection=null"
    selection=''
  fi
  
  while [ -z $selection ]; do
    read -p "Your selection? " selection
    
    isDigit $selection
    exitCode=$?

    # if digit TRUE
    if [ "$exitCode" -eq 1 ]; then
      # if digit within range
      if [[ "$selection" -ge 0 && "$selection" -lt "$roleCount" ]]; then 
        break
      fi
    fi
    selection=''
  done
  
  echo $selection
}


# call AWS sts (security token service) to obtain a temporary set of credentials for CLI/API access
# Input: role_awsARN, role_principal, SAMLResponse
# Result: awsResult
aws_get_sts() {
  if [ $# -lt 1 ]; then
    printf "${red}Error in %s(): insufficient arguments (%d).\n${end}" ${FUNCNAME[0]} $# 
    exit 1
  fi

  local roleIndex=$1

  IFS=''
  awsResult=`aws sts assume-role-with-saml \
    --role-arn ${role_awsARN[$roleIndex]} \
    --principal-arn ${role_principal[$roleIndex]} \
    --saml-assertion $SAMLResponse \
    --duration-seconds 43200`

  
  if [ "$DEBUG" -eq 1 ]; then
    printf "awsResult:\n%s\n" $awsResult
  fi
  
  aws_access_key_id=`echo $awsResult | jq -r '.Credentials.AccessKeyId'`
  aws_secret_access_key=`echo $awsResult | jq -r '.Credentials.SecretAccessKey'`
  aws_session_token=`echo $awsResult | jq -r '.Credentials.SessionToken'`
  aws_token_expiration=`echo $awsResult | jq -r '.Credentials.Expiration'`

  printf "\n"
  #printf "Access Key ID:     %s\n" $aws_access_key_id
  #printf "Secret Access Key: %s\n" $aws_secret_access_key
  if [ $uname = "Darwin" ]; then
    # well, again, because MacOS...
    printf "  ${yel}Temporary token expires on: %s\n${end}" $aws_token_expiration
  else
    printf "  ${yel}Temporary token expires on: %s\n${end}" `date -d"$aws_token_expiration"`
  fi

  printf "\n"
}


# display profiles found in the credentials file
show_credentials_profiles() {
  declare -a profiles 
  local profileCount=''

  # display stuff if credentials file exists
  if [ -f ~/.aws/credentials ]; then
    IFS=$'\n'

    # find profiles and stuff them into an array
    profiles=($(grep '^\[.*\]$' ~/.aws/credentials))
    profileCount=${#profiles[@]}

    printf "AWS profiles found: %s\n" $profileCount 
    for i in "${!profiles[@]}"
      do
        printf " %s\n" ${profiles[$i]}
      done

    printf "\n"
  fi
  
}


# ask user to set aws configuration profile details
# Input: aws_profile_name, aws_profile_region, aws_profile_output
# Result: aws_write_config
prompt_aws_profile_change() {
  local response=''
  local default_profile=''
  declare -a aws_output_options

  aws_output_options=("json" "text" "table")

  local optionCount=${#aws_output_options[@]}

  # check to see if the [default] profile exists
  if [ -f ~/.aws/credentials ]; then
    default_profile=`cat ~/.aws/credentials | grep '^\[default\]$'`
    if [ -n "$default_profile" ]; then
      printf "${yel}Warning, selecting (N)o will overwrite the default config profile.\n\n${end}"
    fi
  fi

  printf "${yel}Default config profile settings include:\n${end}"
  printf "[profile %s]\n" $aws_profile_name
  printf "region = %s\n" $aws_profile_region
  printf "output = %s\n" $aws_profile_output
  printf "\n"

  read -p "Create a custom AWS profile? [y/N]: " response

  # FIXME: Prompt accepts any non yY input as nN.

  if [[ ! ($response == "Y" ||  $response == "y") ]]; then
    # if Y or y not selected, write defaults
    aws_write_config 
    exit 0
  fi

  # change profile name
  response=''
  printf "  Profile name [%s]: " $aws_profile_name
  read response 

  if [ -n "$response" ]; then
    aws_profile_name=$response
  fi

  # change region
  response=''
  printf "  Region [%s]: " $aws_profile_region
  read response

  if [ -n "$response" ]; then
    aws_profile_region=$response
  fi

  # change output format (json, txt)
  printf "  Output Options:\n"
  for i in "${!aws_output_options[@]}" 
    do
      printf "    [%d] %s\n" $i ${aws_output_options[$i]}
    done

  response=''
  read -p "Selection [0]: " response

  if [[ "$response" -ge 0 && "$response" -lt "$optionCount" ]]; then 
    aws_profile_output=${aws_output_options[$response]}
  fi

  if [ "$DEBUG" -eq 1 ]; then
    printf "\n"
    printf "config file settings:\n"
    printf "[profile %s]\n" $aws_profile_name
    printf "region = %s\n" $aws_profile_region
    printf "output = %s\n" $aws_profile_output
    printf "\n"
    printf "credentials file settings:\n"
    printf "[%s]\n" $aws_profile_name
    printf "aws_access_key_id = %s\n" $aws_access_key_id
    printf "aws_secret_access_key = %s\n" $aws_secret_access_key
    printf "aws_session_token = %s\n" $aws_session_token
  fi
 
}


# uses aws cli to write aws configuration details to profile
# Input: aws_access_key_id, aws_secret_access_key, aws_session_token, aws_profile_region, aws_profile_output
# Result: aws_write_config
aws_write_config() {

  # append a newline character if one does not exist
  if [ -f ~/.aws/config ]; then
    if [ ! -z "$(tail -c 1 ~/.aws/config)" ]; then
      echo "" >> ~/.aws/config
    fi
  fi

  if [ -f ~/.aws/credentials ]; then
    if [ ! -z "$(tail -c 1 ~/.aws/credentials)" ]; then
      echo "" >> ~/.aws/credentials
    fi
  fi

  printf "Writing AWS configure data...\n"
  aws configure set aws_access_key_id $aws_access_key_id --profile $aws_profile_name
  aws configure set aws_secret_access_key $aws_secret_access_key --profile $aws_profile_name
  aws configure set aws_session_token $aws_session_token --profile $aws_profile_name
  aws configure set region $aws_profile_region --profile $aws_profile_name
  aws configure set output $aws_profile_output --profile $aws_profile_name
  printf "  ${grn}Success\n${end}"
}


# function that stitches together an interactive flow
mode_interactive() {

  prompt_user_credentials
  
  curl_okta_auth

  parse_mfa_options

  show_mfa_options
    
  process_mfa_option
   
  set_sessionToken

  curl_get_sessionID $uri_okta_sessions $sessionToken

  curl_get_appLinks

  show_app_options
  
  local appIndex=$(prompt_app_selection)
  
  if [ "$DEBUG" -eq 1 ]; then
	show_appDetail_byIndex $appIndex
  fi

  curl_get_appMetaDataURI ${app_instanceId[$appIndex]}

  curl_get_appRoles $uri_okta_metadata $sessionCookie

  show_app_roles
  local roleIndex=$(prompt_role_selection)
  aws_get_sts $roleIndex

  show_credentials_profiles

  prompt_aws_profile_change

  aws_write_config
}


#########################################
# Main
#########################################
while getopts "hd" OPTION; do
  case $OPTION in
    h)
      usage
      exit 0
      ;;
    d)
      DEBUG=1
      ;;
    *)
      INTERACTIVE=1      
      ;;
  esac
done

check_dependencies

mode_interactive

exit 0
