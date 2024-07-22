#! /bin/bash
echo "Installing dependencies..."
sudo cp ./.devcontainer/radrealm.crt /usr/local/share/ca-certificates/radrealm.crt
sudo update-ca-certificates
# Set up aliases
touch /home/node/.bash_aliases
echo alias ll=\'ls -alF\' >> /home/node/.bash_aliases
#chmod +x /home/node/.bashrc
# tsc --watch &
# bash -c node /usr/local/share/npm-global/lib/node_modules/typescript/lib/tsc.js -w &


