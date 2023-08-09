echo function getcert\(\){ wget --content-disposition https://rr-frigate.lan:4141/api/getcertificatepem?id=\$@\; } >> ~/.bash_aliases
echo function getkey\(\){ wget --content-disposition https://rr-frigate.lan:4141/api/getkeypem?id=\$@\; } >> ~/.bash_aliases
echo function getchain\(\){ wget --content-disposition https://rr-frigate.lan:4141/api/chaindownload?id=\$@\; } >> ~/.bash_aliases
echo Shortcuts added - run:
echo source ~/.bash_aliases 
echo to load
echo Most Debian based distros will source .bash_aliases .bash_rc so you only need to do this once.