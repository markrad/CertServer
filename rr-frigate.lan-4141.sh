export CERTSERVER_HOST=https://rr-frigate.lan:4141
export REQUEST_PATH=/api/helper
export AUTH_REQUIRED=1
echo Exported CERTSERVER_HOST=$CERTSERVER_HOST
echo To make this permanent add export CERTSERVER_HOST=$CERTSERVER_HOST to your .bashrc file
echo 
echo To source in one step run
echo "source <(curl ${CERTSERVER_HOST}${REQUEST_PATH})"
echo 
command -v curl &> /dev/null
if [ $? -ne 0 ]; then
    echo *** ERROR *** Command curl is required!
    return 4
fi
if [ $AUTH_REQUIRED == "1" ]; then
    echo "Authentication is required"
    authenticate
fi
function isAuthRequired() {
    auth=$(curl -s --fail-with-body $CERTSERVER_HOST/api/AuthRequired)
    echo $auth
}
function authenticate() {
    echo "Please enter your username and password"
    echo "Username:"
    read -r USERNAME
    echo "Password:"
    read -r -s PASSWORD
    echo
    echo "Authenticating..."
    token=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"userId\":\"${USERNAME}\",\"password\":\"$PASSWORD\"}" $CERTSERVER_HOST/login)
    if [ $? -ne 0 ]; then
        echo "Authentication failed"
        return 4
    fi
    if [[ $token == *"Error"* ]]; then
        echo "Authentication failed"
        echo $token
        return 4
    fi
    token=$(echo $token | tr -d '{' | tr -d '}' | cut -d ':' -f3 | tr -d '"')
    export CERTSERVER_TOKEN="Authorization: Bearer $token"
    echo "Authenticated - header exported as $CERTSERVER_TOKEN"
}
function _get_device() {
    # * internal
    # $1: SAS token generated from connection string
    # $2: IoT hub host name
    # $3: Device to check for existance 
    # Return code: curl return code
    if [ ${#FUNCNAME[@]} -eq 1 ]; then
        echo Error: ${FUNCNAME[0]} is for internal use only
        return 4
    fi
    local sas_token=$1
    local device_id=$3
    local uri="https://${2}/devices/${device_id}?api-version=2020-05-31-preview"
    device=$(curl -s --fail-with-body -H "Authorization: $sas_token" "$uri")
    local res=$?
    echo $device
    return $res
}
function _create_x509_device() {
    # * internal
    # $1: SAS token generated from connection string
    # $2: IoT hub URI
    # $3: Device to create
    # Return code: curl return code
    if [ ${#FUNCNAME[@]} -eq 1 ]; then
        echo Error: ${FUNCNAME[0]} is for internal use only
        return 4
    fi
    local sas_token=$1
    local device_id=$3
    local uri="https://${2}/devices/${device_id}?api-version=2020-05-31-preview"
    body="{\"deviceId\":\"${device_id}\",\"status\":\"enabled\",\"authentication\":{\"type\":\"certificateAuthority\"},\"capabilities\":{\"iotEdge\":false}}"
    device=$(curl -s -X PUT -H "Content-Type: application/json" -H "Authorization: $sas_token" -d "$body" "$uri")
    local res=$?
    echo $device
    return $res
}
function _check_device() {
    # ** internal
    # Checks to see if a device already exists
    # $1: SAS token generated from connection string
    # $2: IoT hub URI
    # $3: Device identity to create
    # Return codes:
    #   0: Device was found in hub
    #   1: Device was not found in hub
    #   2: Error was returned
    #   3: Could not parse response from the hub
    if [ ${#FUNCNAME[@]} -eq 1 ]; then
        echo Error: ${FUNCNAME[0]} is for internal use only
        return 4
    fi
    msg=$(_get_device "$1" "$2" "$3")
    local res=$?
    if [[ $msg == *"ErrorCode"* ]]; then
        if [[ $msg == *"ErrorCode:DeviceNotFound"* ]]; then
            echo Device not found
            return 1
        else
            error_return=$(echo "$msg" | grep -Eoi "ErrorCode:[a-z;]*")
            echo ${error_return:10}
            return 2
        fi
    elif [[ $msg == *"$3"* ]]; then
        echo $msg
        return 0
    else
        echo Unrecognized response: $msg
        return 3
    fi
}
function urlencode() {
    # URL encode the passed string
    # Slow but does the job with minimal dependencies
    # $1: The string to encode
    # Returns the encoded string
    local string="${1}"
    local strlen=${#string}
    local encoded=""
    local pos c o

    for (( pos=0 ; pos<strlen ; pos++ )); do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9] )   o="${c}" ;;
        * )                     printf -v o '%%%02X' "'$c"
        esac
        encoded+="${o}"
    done
    echo "${encoded}"
}
function generate_sas_token() {
    local connection_string="$1"
    # Check we have the required commands available
    command -v openssl &> /dev/null
    if [ $? -ne 0 ]; then
        echo Command openssl is required
        return 4
    fi
    # Extract relevant parts from the connection string
    endpoint=$(echo "$connection_string" | grep -o -E "HostName=([^;]+)" | cut -d'=' -f2)
    key_name=$(echo "$connection_string" | grep -o -E "SharedAccessKeyName=([^;]+)" | cut -d'=' -f2)
    key_value=$(echo "$connection_string" | grep -o -E "SharedAccessKey=([^;]+)" | cut -c17-)
    if [ -z "$endpoint" ] || [ -z "$key_name" ] || [ -z "$key_value" ]; then
        echo Connection string is invalid
        return 4
    else
        # Generate SAS token
        key_hex=$(echo -n $key_value | base64 -d)
        expiry=$(($(date +%s) + 3600))  # Expiry time: current time + 1 hour
        to_encrypt="$endpoint"$'\n'"$expiry"
        signature=$(echo -n "$to_encrypt" | openssl dgst -sha256 -binary -hmac "$key_hex" -binary | base64)
        encoded_signature=$(urlencode $signature)
        token="SharedAccessSignature sr=$endpoint&sig=$encoded_signature&se=$expiry&skn=$key_name"
        echo "$token"
    fi
}
function getservicestatistics() {
    # Queries service statistics
    # $1: SAS token generated from connection string
    # $2: IoT hub URI
    # Return codes:
    #   200: Statistics returned
    #   Other: Call failed
    local sas_token=$1
    local res=$?
    if [ $res -ne 0 ]; then
        echo Error $sas_token
        return 4
    fi
    local url="${2}/statistics/service?api-version=2020-05-31-preview"
    stats=$(curl -s --fail-with-body -H "Authorization: $sas_token" "$url")
    local res=$?
    echo $stats
    return $res
}
function getcertserver() { 
    echo $CERTSERVER_HOST;
}
function getcert() { 
    wget --content-disposition --header="$CERTSERVER_TOKEN" $CERTSERVER_HOST/api/getCertificatePem?id=$@ 2>&1; 
}
function getkey() { 
    wget --content-disposition --header="$CERTSERVER_TOKEN" $CERTSERVER_HOST/api/getKeyPem?id=$@ 2>&1; 
}
function getchain() { 
    wget --content-disposition --header="$CERTSERVER_TOKEN" $CERTSERVER_HOST/api/chainDownload?id=$@ 2>&1; 
}
function pushcert() { 
    curl -X POST -H "$CERTSERVER_TOKEN" -H "Content-Type: text/plain" --data-binary @$@ $CERTSERVER_HOST/api/uploadCert; 
}
function pushkey() { 
    curl -X POST -H "$CERTSERVER_TOKEN" -H "Content-Type: text/plain" --data-binary @$@ $CERTSERVER_HOST/api/uploadKey; 
}
function extractkey() {
    # $1: Output from /api/certdetails
    # Returns:
    #   0: Key found and returned
    #   1: Certificate does not have a key
    #   2: Key not found
    if [[ $1 == *"\"keyId\":null"* ]]; then
        echo Certificate does not have a private key
        return 1
    fi
    FIND_KEY='"keyId":([0-9]*)'
    if [[ $1 =~ $FIND_KEY ]]; then
        echo ${BASH_REMATCH[1]}
        return 0
    else
        echo keyId not found $1
        return 1
    fi
}
function extractid() {
    # $1: Output from /api/certdetails
    # Returns:
    #   0: Key found and returned
    #   1: Key not found
    FIND_ID='"id":([0-9]*)'
    if [[ $1 =~ $FIND_ID ]]; then
        echo ${BASH_REMATCH[1]}
        return 0
    else
        echo id not found $1
        return 1
    fi
}
function extractetag() {
    # $1: Output from IoT Hub devices/<device_id>
    # Returns:
    #   0: etag found and returned
    #   1: etag not found
    FIND_ETAG='"etag":("[a-zA-Z0-9=]*")'
    if [[ $1 =~ $FIND_ETAG ]]; then
        echo ${BASH_REMATCH[1]}
        return 0
    else
        echo etag not found $1
        return 1
    fi
}
function getcertandkey() {
    # Gets the certificate for the certificate id and the associated key
    # $1: Certificate id 
    curlout=$(curl -s -H "$CERTSERVER_TOKEN" "$CERTSERVER_HOST/api/certdetails?id=$1")
    if [ ${#curlout} -eq 0 ]; then
        echo Requested certificate was not found or server error
        return 4
    fi
    key=$(extractkey $curlout)
    res=$?
    if [ $res -ne 0 ]; then
        echo Private key was not found
        return 4
    fi
    echo Getting certificate $1
    getcert $1
    echo Getting key $key
    getkey $key
}
function getchainandkey() {
    # Gets the certificate chain for the certificate id and the associated key
    # $1: Certificate id of lowest level certficate
    curlout=$(curl -s --fail-with-body -H "$CERTSERVER_TOKEN" "$CERTSERVER_HOST/api/certdetails?id=$1")
    res=$?
    if [ $res -ne 0 ]; then
        echo Requested certificate was not found or server error: $curlout
        return 4
    fi
    key=$(extractkey $curlout)
    res=$?
    if [ $res -ne 0 ]; then
        echo Private key was not found
        return 4
    fi
    echo Getting certificate chain $1
    getchain $1
    echo Getting key $key
    getkey $key
}
function getcertdetailsbyname() {
    # Returns a certificate by its common name if there is only one
    # $1: Certificate common name
    # Returns:
    # 0: Certificate details returned in JSON format
    # 1: Multiple matching certificates - ids returned as { "error: "<message>", "ids": [nnn,mmm,...] }
    # 2: Certificate does not exist
    # 3: CertServer returned an error - returns { "error": "<message" }
    # 4: Missing arguments
    if [ -z "$1" ]; then
        echo Missing arguments
        echo "Usage getcertdetailsbyname <device identity>"
        return 4
    fi
    curlout=$(curl -s --fail-with-body -H "$CERTSERVER_TOKEN" -w "%{http_code}" "$CERTSERVER_HOST/api/certdetails?name=$1")
    res=$?
    curloutlen=${#curlout}
    curlresp=${curlout:0:$curloutlen-3}
    curlstatus=${curlout:$curloutlen-3}
    if [ $res -eq 22 ] && [ $curlstatus -eq "404" ]; then
        echo Certificate does not exist
        return 2
    elif [[ $curlresp == *"Multiple certificates"* ]]; then
        echo $curlresp
        return 1
    elif [ $res -ne 0 ]; then
        echo $curlresp
        return 3
    else
        echo $curlresp
        return 0
    fi
}
function remdevice() {
    # Removes the device from the hub and the associated certificate from the certserver if there is one
    # $1: Connection string
    # $2: Device identity
    set connection_string=$1
    set device_id=$2
    if [ -z "$connection_string" ] || [ -z "$device_id" ]; then
        echo Missing arguments
        echo "Usage remdevice <connection string> <device identity>"
        return 4
    fi
    details=$(getcertdetailsbyname $device_id)
    res=$?
    if [ $res -eq 1 ]; then
        echo Multiple certificates for $device_id - cannot continue
        return 4
    elif [ $res -eq 2 ]; then
        echo Certificate does not exist - will delete device
    elif [ $res -eq 3 ]; then
        echo An error occured: $details
        return 4
    elif [ $res -eq 0 ]; then
        key=$(extractkey $details)
        res=$?
        if [ $res -eq 1 ]; then
            echo Private key was not found
        else
            echo Deleting key $key
            curlout=$(curl -X DELETE -s --fail-with-body "$CERTSERVER_HOST/api/deletekey?id=$key")
            res=$?
            if [ $res -ne 0 ]; then
                echo Key delete failed: $curlout
                return 4
            fi
            echo Key deleted
        fi
        id=$(extractid $details)
        res=$?
        if [ $res -ne 0 ]; then
            echo $id
            return 4
        fi
        echo Deleting certificate $id
        curlout=$(curl -X DELETE -s --fail-with-body "$CERTSERVER_HOST/api/deletecert?id=$id")
        res=$?
        if [ $res -ne 0 ]; then
            echo Certificate delete failed: $curlout
            return 4
        fi
        echo Certificate deleted
    fi
    echo Deleting device $device_id
    sas_token=$(generate_sas_token $connection_string)
    res=$?
    if [ $res -ne 0 ]; then
        echo $sas_token
        return $res
    fi
    hub_uri=$(echo "$1" | grep -o -E "HostName=([^;]+)" | cut -d'=' -f2)
    device=$(_get_device "$sas_token" "$hub_uri" "$device_id")
    res=$?
    if [ $res -ne 0 ]; then
        echo Cannot find device: $device
        return 4
    fi
    etag=$(extractetag $device)
    res=$?
    if [ $res -ne 0 ]; then
        echo $etag
        return 4
    fi
    local uri="https://${hub_uri}/devices/{$device_id}?api-version=2020-05-31-preview"
    device=$(curl -s -X DELETE -H "Authorization: $sas_token" -H "If-Match: $etag" "$uri")
    local res=$?
    if [ $res -eq 0 ]; then
        echo "Device ${device_id} deleted"
    else
        echo "Failed to delete device ${device_id}: ${device}"
    fi
}
function gendevice() {
    # Creates a device and generates X.509 certificate and key for authorization with the hub
    # $1: Connection string
    # $2: Certserver id of IoT hub root certificate
    # $3: New device identity
    connection_string=$1
    root_id=$2
    device_id=$3
    if [ -z "$connection_string" ] || [ -z "$root_id" ] || [ -z "$device_id" ]; then
        echo Missing arguments
        echo "Usage gendevice <connection string> <root certificate id> <new device identity>"
        return 4
    fi
    details=$(getcertdetailsbyname "$device_id")
    res=$?
    if [ $res -eq 0 ]; then
        echo Certificate for $device_id already exists
        return 4
    elif [ $res -ne 2 ]; then
        echo An error occured: $details
        return 4
    fi
    sas_token=$(generate_sas_token "$connection_string")
    res=$?
    if [ $res -ne 0 ]; then
        echo $sas_token
        return $res
    fi
    hub_uri=$(echo "$connection_string" | grep -o -E "HostName=([^;]+)" | cut -d'=' -f2)
    msg=$(_check_device "$sas_token" "$hub_uri" "$device_id")
    res=$?
    if [ "$res" -eq 0 ]; then
        echo Device already exists
        return 4
    elif [ "$res" -ne 1 ]; then
        echo Return code $res
        echo $msg
        return $res
    fi
    echo Creating device $3
    msg=$(_create_x509_device "$sas_token" "$hub_uri" "$device_id")
    res=$?
    if [ "$res" -ne 0 ]; then
        echo Failed to create $device_id: rc = $res
        echo $msg
        return 4
    elif [[ $msg == *"ErrorCode"* ]]; then
        echo Failed to create $device_id
        error_return=$(echo "$msg" | grep -Eoi "ErrorCode:[a-z;]*")
        echo ${error_return:10}
        return 4
    fi
    echo Device $device_id created
    echo Creating certificate
    validto=$(date --date='+365 days' +'%m/%d/%Y')
    body="{\"signer\":\"$2\",\"commonName\":\"$3\",\"validTo\":\"$validto\"}"
    newcert=$(curl -s --fail-with-body -X POST -H "Content-Type: application/json" -d "$body" "$CERTSERVER_HOST/api/createleafcert")
    res=$?
    if [ $res -eq 0 ]; then
        echo Certificate created
        echo Downloading
        id=$(echo $newcert | grep -io '"ids":{"certificateId":[0-9]*')
        id=${id:23}
        echo Downloading certificate chain and key
        getchainandkey $id
    else
        echo Certificate creation failed: $newcert
    fi
}
function getdevice() {
    # Gets a device from the hub by device identity
    # $1: Connection string
    # $2: Device identity
    sas_token=$(generate_sas_token $1)
    res=$?
    if [ $res -ne 0 ]; then
        echo $sas_token
        return $res
    fi
    hub_uri=$(echo "$1" | grep -o -E "HostName=([^;]+)" | cut -d'=' -f2)
    device=$(_get_device "$sas_token" "$hub_uri" "$2")
    local res=$?
    echo $device
}
