# This Makefile.am is in the public domain
#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif

if HAVE_TESTING
 TESTING = testing
 TESTBED = testbed-logger testbed
 ATS_TESTS = ats-tests
endif

if HAVE_EXPERIMENTAL
 EXP_DIR = \
  dv \
  rps
endif

if HAVE_JSON
if HAVE_MHD
  PROVIDER_DIR = identity-provider
endif
endif

if HAVE_JSON
  JSON_DIR = json
if HAVE_LIBGNURL
  JSON_DIR += curl
else
if HAVE_LIBCURL
  JSON_DIR += curl
endif
endif
endif

if BUILD_PULSE_HELPERS
CONVERSATION_DIR = conversation
else
if BUILD_GST_HELPERS
CONVERSATION_DIR = conversation
endif
endif

if HAVE_SQLITE
 SQLITE_DIR = sq
endif

if HAVE_MYSQL
 MYSQL_DIR = mysql my
endif

if HAVE_POSTGRESQL
 POSTGRES_DIR = pq 
endif

if HAVE_MHD
 REST_DIR = rest
if HAVE_JSON
 JSONAPI_DIR = jsonapi
endif
endif

if HAVE_JSON
  AUCTION_DIR = auction
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
  $(JSONAPI_DIR) \
  hello \
  tun \
  block \
  statistics \
  arm \
  $(TESTING) \
  peerinfo \
  $(SQLITE_DIR) \
  $(MYSQL_DIR) \
  $(POSTGRES_DIR) \
  datacache \
  datastore \
  template \
  ats \
  nat \
  nat-auto \
  fragmentation \
  transport \
  ats-tool \
  peerinfo-tool \
  core \
  $(TESTBED) \
  $(ATS_TESTS) \
  nse \
  dht \
  hostlist \
  topology \
  regex \
  dns \
  identity \
  gnsrecord \
  namecache \
  namestore \
  peerstore \
  cadet \
  set \
  consensus \
  scalarproduct \
  revocation \
  vpn \
  gns \
  zonemaster \
  $(CONVERSATION_DIR) \
  fs \
  exit \
  pt \
  secretsharing \
  integration-tests \
  multicast \
  psycutil \
  psycstore \
  psyc \
  social \
  $(AUCTION_DIR) \
  $(EXP_DIR) \
  $(PROVIDER_DIR)

endif
