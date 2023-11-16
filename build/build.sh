#!/bin/bash

function help() {
    echo Usage:
    echo " $0 <options> <repository>"
    echo
    echo "Update version number in Dockerfile and package.json"
    echo "Commit changes to GitHub and tag with new version number"
    echo
    echo Options:
    echo " -M, --major          Update major version"
    echo " -m, --minor          Update minor version"
    echo " -p, --patch          Update patch version"
    echo " -h, --help           Print this message"
    echo
    echo --major, --minor, and --patch are mutually exclusive
    echo
    echo If the repository is not provided it will default to rr-frigate.lan
    # echo "--- $field $repo"
    exit 4
}

LGREEN='\033[0;31m'
RESET='\033[0m'
field=99
# hadrepo=0
# repo="rr-frigate.lan"

if [[ -n $(git status -s) ]]
then
    echo Cannot run build with outstanding changes to be committed
    exit 4
fi

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
                    echo "--major, --minor, and --patch are mutually exclusive"
                    help
                else
                    field=0
                fi
                ;;
            -m | --minor)
                if [ $field -ne 99 ]
                then
                    echo "--major, --minor, and --patch are mutually exclusive"
                    help
                else
                    field=1
                fi
                ;;
            -p | --patch)
                if [ $field -ne 99 ]
                then
                    echo "--major, --minor, and --patch are mutually exclusive"
                    help
                else
                    field=2
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

echo This will update the version from $version to $newver and push a new tag
read -p "$(echo -e Do you wish to continue? ${LGREEN}Yes - y${RESET} No - n)" response

if [ $response != "Y" ] && [ $response != "y" ]
then
    echo Exiting
    exit 4
fi

echo Running tests
pwd
node ../output/src/tests/tests.js
testrc=$?

if [ $testrc -ne 0 ]
then
    echo Tests failed - exiting
    exit 4
else
    echo Tests complete
fi

echo Updating

sed -i "s/${sedver}/${newver}/" ../docker/Dockerfile
sed -i "s/${sedver}/${newver}/" ../docker/docker-compose.yml
sed -i "3,3 s/${sedver}/${newver}/" ../package.json

git add --verbose ../docker/Dockerfile ../docker/docker-compose.yml ../package.json && \
git commit -m ":bookmark: Bump version to v$newver" && \
git push && \
git tag v$newver && \
git push origin v$newver

echo Finished
