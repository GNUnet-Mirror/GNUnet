# This Makefile.am is in the public domain
#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif

if HAVE_TESTING
 TESTING = testing
 TESTBED = testbed
 CONSENSUS = consensus
 SECRETSHARING = secretsharing
endif

if HAVE_EXPERIMENTAL
 EXP_DIR = \
  dv \
  multicast \
  psycutil \
  psycstore \
  psyc \
  rps \
  social \
  $(CONSENSUS) \
  $(SECRETSHARING) 
endif

if HAVE_REST
  PROVIDER_DIR = identity-provider
endif

if HAVE_JSON
  JSON_DIR = json
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
 POSTGRES_DIR = pq postgres
endif

if HAVE_REST
 REST_DIR = rest
endif

if TALER_ONLY
SUBDIRS = \
 include \
 util
else

SUBDIRS = \
  include $(INTLEMU_SUBDIRS) \
  util \
  $(JSON_DIR) \
  $(REST_DIR) \
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
  $(PROVIDER_DIR)

endif
