#!/bin/sh
user=$(whoami)
gnunet_proxy=$(gnunet-config -c /etc/skel/.config/gnunet.conf -s gns-proxy|grep 'IMMEDIATE_START = YES')

# Enable GNS proxy for new users informed by /etc/skel (system wide 
# installation decision).
if [ "$gnunet_proxy" ]; then

	# Calculate user specific port
	port=$((8000+$(id -u $user)))

	gnunet-config -c /home/$user/.config/gnunet.conf \
		--rewrite \
		--section=gns-proxy \
		--option=OPTIONS \
		--value="-p $port"

	# Firefox
	if [ ! -d  ~/.mozilla/firefox/*.default ];then
		timeout 3s firefox --headless # dirty: create profile if not existent
	fi
	for ffprofile in ~/.mozilla/firefox/*.*/; do
		js=$ffprofile/user.js
		if [ -f $js ]; then
			sed -i '/Preferences for using the GNU Name System/d' $js
			sed -i '/network.proxy.socks/d' $js
			sed -i '/network.proxy.socks_port/d' $js
			sed -i '/network.proxy.socks_remote_dns/d' $js
			sed -i '/network.proxy.type/d' $js
		fi
		echo "// Preferences for using the GNU Name System" >> $js
		echo "user_pref(\"network.proxy.socks\", \"localhost\");" >> $js
		echo "user_pref(\"network.proxy.socks_port\", $port);" >> $js
		echo "user_pref(\"network.proxy.socks_remote_dns\", true);" >> $js
		echo "user_pref(\"network.proxy.type\", 1);" >> $js
	done

	# Chromium
	profile=/home/$user/.profile
	if [ -f $profile ]; then
		sed -i '/CHROMIUM_USER_FLAGS/d' $profile
	fi
	echo "export CHROMIUM_USER_FLAGS=--proxy-server=socks5://localhost:$port" \
		>> $profile
fi

# Create/Renew GNS certificate authority (CA) per user.
gnunet-gns-proxy-setup-ca
