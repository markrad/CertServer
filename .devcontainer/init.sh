#! /bin/bash
echo "Installing dependencies..."
sudo cp ./.devcontainer/radrealm.crt /usr/local/share/ca-certificates/radrealm.crt
sudo update-ca-certificates
# tsc --watch &
# bash -c node /usr/local/share/npm-global/lib/node_modules/typescript/lib/tsc.js -w &


