# This Makefile.am is in the public domain
#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif

if HAVE_TESTING
 TESTING = testing
 TESTBED = testbed
 CONSENSUS = consensus
 SECRETSHARING = secretsharing
 SENSOR = sensor
 SENSORDASHBOARD = sensordashboard
endif

if HAVE_EXPERIMENTAL
 EXP_DIR = \
  dv \
  multicast \
  env \
  psycstore \
  psyc \
  rps \
  social \
  $(CONSENSUS) \
  $(SECRETSHARING) \
  $(SENSOR) \
  $(SENSORDASHBOARD)
endif

if HAVE_WACHS
  WACHS_DIR = \
    ats-tests
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

if HAVE_POSTGRESQL
 POSTGRES_DIR = postgres
endif

if HAVE_REST
 REST_DIR = rest
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
  $(REST_DIR) \
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
  cadet \
  dns \
  identity \
  set \
  scalarproduct \
  revocation \
  gnsrecord \
  namecache \
  namestore \
  vpn \
  gns \
  $(CONVERSATION_DIR) \
  peerstore \
  fs \
  exit \
  pt \
  integration-tests \
  $(EXP_DIR) \
  $(WACHS_DIR)
