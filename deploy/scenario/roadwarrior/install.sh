#!/bin/bash

INSTALLDIR="/usr/local"
CONFIGPATH="$INSTALLDIR/etc"
PEER=192.168.199.101


echo -e "\033[32mInstall certificate...\033[0m"
cp carol/swanctl.conf $CONFIGPATH/swanctl/ 
sshpass -pnsfocus scp moon/swanctl.conf $PEER:$CONFIGPATH/swanctl/
