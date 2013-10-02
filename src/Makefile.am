#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif

if HAVE_TESTING
 TESTING = testing
 TESTBED = testbed
 CONSENSUS = consensus
 EXPERIMENTATION = experimentation
 SCALARPRODUCT = scalarproduct
endif

if HAVE_EXPERIMENTAL
 EXP_DIR = \
  dv \
  multicast \
  env \
  psyc \
  $(CONSENSUS) \
  $(EXPERIMENTATION)
  # NOTE: scalarproduct is not being listed here yet as the crypto is being reworked at the moment
if HAVE_PULSE
if HAVE_OPUS
  EXP_DIR += conversation
endif
endif

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
  ats-tests \
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
  revocation \
  namestore \
  vpn \
  gns \
  psycstore \
  fs \
  exit \
  pt \
  integration-tests \
  $(EXP_DIR) 
