#!/bin/bash

IPTABLES_CHAIN_NAME="Drop-From-TOR1";
BAD_IPS_FILE="badips.db"
BAD_IPS_URL="https://www.dan.me.uk/torlist"

MAIL_FROM="report.to@domain.com";
MAIL_TO="Report To <report.to@domain.com>";
MAIL_SUBJECT="[BAN_TOR_IPS] Execution failed";
MAIL_BODY="Unable to download file from $BAD_IPS_URL";
MAIL_USER="username";
MAIL_PASSWORD="password";
MAIL_SERVER="correo.report.to:2525";

WGET_LOG="/tmp/wget.log"

# Download list of IPs
wget_output=$(wget -q $BAD_IPS_URL -O $BAD_IPS_FILE -o $WGET_LOG)
if [ $? -ne 0 ]; then
	echo "Unable to download file from $BAD_IPS_URL"
	sendEmail -q -o message-content-type=text tls=auto -f $MAIL_FROM -t $MAIL_TO -s $MAIL_SERVER -xu $MAIL_USER -xp $MAIL_PASSWORD -u $MAIL_SUBJECT -m $MAIL_BODY -a $WGET_LOG
	exit 1
fi

# Create/Flush specific iptables chain
iptables -N $IPTABLES_CHAIN_NAME 2> /dev/null
iptables -F $IPTABLES_CHAIN_NAME
ip6tables -N $IPTABLES_CHAIN_NAME 2> /dev/null
ip6tables -F $IPTABLES_CHAIN_NAME
# Forward incoming traffic to the new chain
iptables -C INPUT -s 0.0.0.0/0 -j $IPTABLES_CHAIN_NAME 2> /dev/null
if [ $? -ne 0 ]; then
	iptables -I INPUT -s 0.0.0.0/0 -j $IPTABLES_CHAIN_NAME
fi
ip6tables -C INPUT -s ::/0 -j $IPTABLES_CHAIN_NAME 2> /dev/null
if [ $? -ne 0 ]; then
	ip6tables -I INPUT -s ::/0 -j $IPTABLES_CHAIN_NAME
fi
# Add IPs to the new chain
while read ipaddr
do
	echo "Banning $ipaddr"
	# Check IP address version
	# https://helloacm.com/how-to-valid-ipv6-addresses-using-bash-and-regex/
	if [[ $ipaddr =~ ^([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then
		#echo "IPv4 $ipaddr"
		iptables -I $IPTABLES_CHAIN_NAME -s $ipaddr -j DROP
 	elif [[ $ipaddr =~ ^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$ ]]; then
        #echo "IPv6 $ipaddr"
		ip6tables -I $IPTABLES_CHAIN_NAME -s $ipaddr -j DROP
	else
        echo "Unrecognized IP format '$ipaddr'"
	fi
# Choose if you want to check for uniqueness
#done < $BAD_IPS_FILE | sort | uniq
done < $BAD_IPS_FILE

iptables -A $IPTABLES_CHAIN_NAME -j RETURN
ip6tables -A $IPTABLES_CHAIN_NAME -j RETURN

# Check everything was done correctly
# iptables -n -L $IPTABLES_CHAIN_NAME
# ip6tables -n -L $IPTABLES_CHAIN_NAME
