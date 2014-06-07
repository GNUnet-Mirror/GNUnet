#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif

if HAVE_TESTING
 TESTING = testing
 TESTBED = testbed
 CONSENSUS = consensus
 SECRETSHARING = secretsharing
 EXPERIMENTATION = experimentation
 SCALARPRODUCT = scalarproduct
 SENSOR = sensor
 PEERSTORE = peerstore
endif

if HAVE_EXPERIMENTAL
 EXP_DIR = \
  dv \
  multicast \
  env \
  psycstore \
  psyc \
  social \
  $(CONSENSUS) \
  $(SECRETSHARING) \
  $(SCALARPRODUCT) \
  $(EXPERIMENTATION) \
  $(PEERSTORE) \
  $(SENSOR)
endif


if BUILD_PULSE_HELPERS
CONVERSATION_DIR = conversation
else
if BUILD_GST_HELPERS
CONVERSATION_DIR = conversation
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
  cadet \
  dns \
  identity \
  set \
  revocation \
  gnsrecord \
  namecache \
  namestore \
  vpn \
  gns \
  $(CONVERSATION_DIR) \
  fs \
  exit \
  pt \
  integration-tests \
  $(EXP_DIR)
