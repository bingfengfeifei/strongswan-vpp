#!/bin/bash

INSTALLDIR="/usr/local"
CONFIGPATH="$INSTALLDIR/etc"
SERVER_HOST=moon.strongswan.org
SERVER_IP=192.168.0.1
CLIENT_HOST=carol@strongswan.org
CLIENT_IP=192.168.0.2

PEER=192.168.199.101

# remove old files
rm -rf cert > /dev/null 2>&1
mkdir cert && cd cert

# create CA certificate
echo -e "\033[32mCreate CA certificate...\033[0m"
pki --gen --outform pem > ca.key.pem
pki --self --in ca.key.pem --dn "C=CN, O=StrongSwan, CN=StrongSwan CA" --ca --outform pem > ca.cert.pem

# create server certificate
echo -e "\033[32mCreate server certificate...\033[0m"
pki --gen --outform pem > server.key.pem
pki --pub --in server.key.pem | ipsec pki --issue --cacert ca.cert.pem \
  --cakey ca.key.pem --dn "C=CN, O=StrongSwan, CN=$VPNHOST" \
  --san "$SERVER_HOST" --san="$SERVER_IP" --flag serverAuth --flag ikeIntermediate \
  --outform pem > server.cert.pem

# create client certificate
echo -e "\033[32mCreate client certificate...\033[0m"
pki --gen --outform pem > client.key.pem
pki --pub --in client.key.pem | ipsec pki --issue --cacert ca.cert.pem \
  --cakey ca.key.pem --dn "C=CN, O=StrongSwan, CN=carol@strongswan.org" \
  --san "$CLIENT_HOST" --san="CLIENT_IP" \
  --outform pem > client.cert.pem

echo -e "\033[32mInstall certificate...\033[0m"
cp ca.cert.pem $CONFIGPATH/swanctl/x509ca/strongswanCert.pem 
cp client.cert.pem $CONFIGPATH/swanctl/x509/carolCert.pem 
cp client.key.pem $CONFIGPATH/swanctl/private/carolKey.pem 

sshpass -pnsfocus scp ca.cert.pem $PEER:$CONFIGPATH/swanctl/x509ca/strongswanCert.pem 
sshpass -pnsfocus scp server.cert.pem $PEER:$CONFIGPATH/swanctl/x509/moonCert.pem
sshpass -pnsfocus scp server.key.pem $PEER:$CONFIGPATH/swanctl/private/moonKey.pem
