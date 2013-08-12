#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif

if HAVE_TESTING
 TESTING = testing
 TESTBED = testbed
 CONSENSUS = consensus
 EXPERIMENTATION = experimentation
endif

if HAVE_EXPERIMENTAL
 EXP_DIR = dv $(CONSENSUS) $(EXPERIMENTATION) 
endif

if LINUX
# All of these currently only work on GNU/Linux or W32
 LINUX_DIR = exit vpn
# pt # without namestore, pt currently has some issues...
endif
if MINGW
 MINGW_DIR = vpn exit 
# pt # without namestore, pt currently has some issues...
endif

if HAVE_MYSQL
 MYSQL_DIR = mysql
endif

if HAVE_POSTGRES
 POSTGRES_DIR = postgres
endif


SUBDIRS = \
  include $(INTLEMU_SUBDIRS) \
  util \
  hello \
  tun \
  block \
  statistics \
  arm \
  $(TESTING) \
  peerinfo \
  $(MYSQL_DIR) \
  $(POSTGRES_DIR) \
  datacache \
  datastore \
  template \
  ats \
  nat \
  fragmentation \
  transport \
  ats-tool \
  peerinfo-tool \
  core \
  $(TESTBED) \
  nse \
  dht \
  hostlist \
  topology \
  regex \
  mesh \
  lockmanager \
  dns \
  identity \
  set \
  fs \
  $(LINUX_DIR) \
  $(MINGW_DIR) \
  integration-tests \
  $(EXP_DIR) 

# note: namestore, gns are not listed right now as they are being reworked to use the new crypto