#!/usr/bin/python
import pexpect
import os
import signal
import re

os.system ('gnunet-arm -s')
try:
# first, basic publish-search-download run
  pub = pexpect.spawn ('gnunet-publish -k gpl ../../COPYING')
  pub.expect ('Publishing `../../COPYING\' done.\r')
  pub.expect ("URI is `gnunet://fs/chk/PC0M19QMQC0BPSHR6BGA228PP6INER1D610MGEMOMEM87222FN8HVUO7PQGO0O9HD2GVLHF2N5IDHEQUNK6LKE428FPO96SKQEA486O.PG7K85JGQ6N599MD5HEP3CHEVFPKQD9JB6NPSLVA3T1SKDS66CFI499VS6MGQ88B0QUAVT1282TCRD4GGFVUKDLGI8F0SPIANA3J2LG.35147'.\r")
  pub.expect (pexpect.EOF)

  search = pexpect.spawn ('gnunet-search gpl')
  search.expect ("gnunet-download -o \"COPYING\" gnunet://fs/chk/PC0M19QMQC0BPSHR6BGA228PP6INER1D610MGEMOMEM87222FN8HVUO7PQGO0O9HD2GVLHF2N5IDHEQUNK6LKE428FPO96SKQEA486O.PG7K85JGQ6N599MD5HEP3CHEVFPKQD9JB6NPSLVA3T1SKDS66CFI499VS6MGQ88B0QUAVT1282TCRD4GGFVUKDLGI8F0SPIANA3J2LG.35147\r")
  search.kill (signal.SIGTERM)
  search.expect (pexpect.EOF)
# FIXME: check for meta-data (also need to add meta data in publish call!)
  
  down = pexpect.spawn ('gnunet-download -o \"COPYING\" gnunet://fs/chk/PC0M19QMQC0BPSHR6BGA228PP6INER1D610MGEMOMEM87222FN8HVUO7PQGO0O9HD2GVLHF2N5IDHEQUNK6LKE428FPO96SKQEA486O.PG7K85JGQ6N599MD5HEP3CHEVFPKQD9JB6NPSLVA3T1SKDS66CFI499VS6MGQ88B0QUAVT1282TCRD4GGFVUKDLGI8F0SPIANA3J2LG.35147')
  down.expect (re.compile ("Downloading `COPYING\' done \(.*\).\r"));
  down.expect (pexpect.EOF);
  os.system ('rm COPYING');

# second, same with namespace creation  
  pseu = pexpect.spawn ('gnunet-pseudonym -C licenses -k gpl -k test -m "description:Free Software Licenses"')
  pseu.expect (pexpect.EOF)
  pseu = pexpect.spawn ('gnunet-pseudonym -o')
  pseu.expect (re.compile("licenses \(.*\)\r"))
  pseu.expect (pexpect.EOF)

  pub = pexpect.spawn ('gnunet-publish -k licenses -P licenses -u gnunet://fs/chk/PC0M19QMQC0BPSHR6BGA228PP6INER1D610MGEMOMEM87222FN8HVUO7PQGO0O9HD2GVLHF2N5IDHEQUNK6LKE428FPO96SKQEA486O.PG7K85JGQ6N599MD5HEP3CHEVFPKQD9JB6NPSLVA3T1SKDS66CFI499VS6MGQ88B0QUAVT1282TCRD4GGFVUKDLGI8F0SPIANA3J2LG.35147 -t gpl -N gpl3')
  pub.expect (pexpect.EOF)

#  search = pexpect.spawn ('gnunet-search licenses')
# FIXME: check that namespace was found
# FIXME: check for meta-data!

finally:
  os.system ('gnunet-arm -e')
