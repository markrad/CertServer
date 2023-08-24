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
read -p "Do you wish to continue? [Yy] " response

if [ $response != "Y" ] && [ $response != "y" ]
then
    echo Exiting
    exit 4
fi

# echo Testing npm install
# npm install --dry-run || { echo 'npm install failed' ; exit 1; }

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

sed -i "s/${version}/${newver}/" ../docker/dockerfile
sed -i "s/${version}/${newver}/" ../docker/docker-compose.yml
sed -i "3,3 s/${version}/${newver}/" ../package.json

git add --verbose ../docker/dockerfile ../docker/docker-compose.yml ../package.json && \
git commit -m ":bookmark: Bump version to $newver" && \
git push && \
git tag v$newver && \
git push origin v$newver

echo Finished

# if ! docker buildx build --platform linux/arm/v7,linux/amd64 --tag $repo/nodedaemon:$newver /home/markrad/source/nodedaemon/build --push
# then
#     echo Docker build and push failed
#     help
# fi
