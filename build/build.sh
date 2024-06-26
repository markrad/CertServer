#!/bin/bash

function help() {
    echo Usage:
    echo " $0 <options> <repository>"
    echo
    echo "Update version number in Dockerfile and package.json"
    echo "Commit changes to GitHub and tag with new version number"
    echo
    echo Options:
    echo " -t, --test           Just run tests - do not update version"
    echo " -M, --major          Update major version"
    echo " -m, --minor          Update minor version"
    echo " -p, --patch          Update patch version"
    echo " -h, --help           Print this message"
    echo
    echo --test, --major, --minor, and --patch are mutually exclusive
    echo
    echo If the repository is not provided it will default to rr-frigate.lan
    # echo "--- $field $repo"
    exit 4
}

LGREEN='\033[1;32m'
LRED='\033[1;31m'
RESET='\033[0m'
field=99
# hadrepo=0
# repo="rr-frigate.lan"

if [ $# -eq 0 ]
then
    field=2
elif [ $# -gt 2 ]
then
    echo Invalid parameters - only two are allowed
    help
else
    while (( "$#" )); do
        case $1 in
            -h | --help)
                help
                ;;
            -M | --major)
                if [ $field -ne 99 ]
                then
                    echo "--test, --major, --minor, and --patch are mutually exclusive"
                    help
                else
                    field=0
                fi
                ;;
            -m | --minor)
                if [ $field -ne 99 ]
                then
                    echo "--test, --major, --minor, and --patch are mutually exclusive"
                    help
                else
                    field=1
                fi
                ;;
            -p | --patch)
                if [ $field -ne 99 ]
                then
                    echo "--test, --major, --minor, and --patch are mutually exclusive"
                    help
                else
                    field=2
                fi
                ;;
            -t | --test)
                if [ $field -ne 99 ]
                then
                    echo "--test, --major, --minor, and --patch are mutually exclusive"
                    help
                else
                    field=3
                fi
                ;;
            *)
                if [ "${1:0:1}" == "-" ]
                then
                    echo "Unknown option $1"
                    help
                fi
                # if [ $hadrepo -ne 0 ]
                # then
                #     echo "Multiple repositories specified"
                #     help
                # fi
                # repo=$1
                # hadrepo=1
                # ;;
        esac
        shift
    done
fi

if [ $field -ne 3 ]
then
    if [[  -n $(git status -s) ]]
    then
        echo Cannot run build with outstanding changes to be committed
        exit 4
    fi

    version=$(jq .version ../package.json | tr -d '"')
    IFS="." read -a parts <<< $version
    printf -v sedver '\.%s' "${parts[@]}"
    sedver=${sedver:2}
    parts[$field]=$((${parts[$field]}+1))

    if [ $field -lt 2 ]
    then
        parts[2]='0'
    fi
    if [ $field -lt 1 ]
    then
        parts[1]='0'
    fi
    newver=$(IFS="." ; echo "${parts[*]}")

    echo -e "This will update the version from ${LGREEN}${version}${RESET} to ${LRED}${newver}${RESET} and push a new tag"
    read -p "$(echo -e Do you wish to continue? ${LGREEN}Yes${RESET} or No [${LGREEN}Y/${RESET}N] ) " response

    if [ "$response" != "Y" ] && [ "$response" != "y" ] && [ "$response" != "" ]
    then
        if [ "$response" != "N" ] && [ "$response" != "n" ]
        then    
            echo Invalid response $response
        fi

        echo Exiting
        exit 4
    fi
fi

echo Running tests
pushd ..
LOG_SERVER_STDOUT="1" \
RUN_API_TESTS="1" \
RUN_BASH_HELPER_TESTS="1" \
RUN_POWERSHELL_HELPER_TESTS="1" \
RUN_IOTHUB_TESTS="0" \
node output/src/tests/tests.js

testrc=$?
popd

if [ $testrc -ne 0 ]
then
    echo -e ${LRED}Tests failed - exiting${RESET}
    exit 4
else
    echo -e ${LGREEN}Tests complete${RESET}
fi

if [ $field -ne 3 ]
then
    echo Updating

    sed -i "s/${sedver}/${newver}/" ../docker/Dockerfile
    sed -i "s/${sedver}/${newver}/" ../docker/docker-compose.yml
    sed -i "3,3 s/${sedver}/${newver}/" ../package.json

    git add --verbose ../docker/Dockerfile ../docker/docker-compose.yml ../package.json && \
    git commit -m ":bookmark: Bump version to v$newver" && \
    git push && \
    git tag v$newver && \
    git push origin v$newver
fi

echo Finished
