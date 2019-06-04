message(STATUS
"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
IMPORTANT:

Please make sure NOW that you have created a user and group 'gnunet'
and additionally a group 'gnunetdns'. On Debian and Ubuntu GNU/Linux,
type:

  addgroup gnunetdns
  adduser --system --group --disabled-login --home /var/lib/gnunet gnunet

Make sure that '/var/lib/gnunet' is owned (and writable) by user
'gnunet'.  Then, you can compile GNUnet with

  make

After that, run (if necessary as 'root')

  make install

to install everything.

Each GNUnet user should be added to the 'gnunet' group (may
require fresh login to come into effect):

  adduser USERNAME gnunet

(run the above command as root once for each of your users, replacing
\"USERNAME\" with the respective login names).  If you have a global IP
address, no further configuration is required.

For more detailed setup instructions, see https://docs.gnunet.org/

Optionally, download and compile gnunet-gtk to get a GUI for
file-sharing and configuration.  This is particularly recommended
if your network setup is non-trivial, as gnunet-setup can be
used to test in the GUI if your network configuration is working.
gnunet-setup should be run as the \"gnunet\" user under X.  As it
does very little with the network, running it as \"root\" is likely
also harmless.  You can also run it as a normal user, but then
you have to copy \"~/.gnunet/gnunet.conf\" over to the \"gnunet\" user's
home directory in the end.

Once you have configured your peer, run (as the 'gnunet' user)

  gnunet-arm -s

to start the peer.  You can then run the various GNUnet-tools as
your \"normal\" user (who should only be in the group 'gnunet').
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
