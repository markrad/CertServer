#! /bin/bash
echo "Installing dependencies..."
sudo cp ./.devcontainer/radrealm.crt /usr/local/share/ca-certificates/radrealm.crt
sudo update-ca-certificates
tsc --watch


