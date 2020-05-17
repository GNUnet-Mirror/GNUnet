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
  rps \
  abd
if HAVE_ABE
 EXP_DIR += \
  abe
endif
 EXP_DIR += \
  auction
endif

JSON_DIR = json
CURL_DIR = curl

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

REST_DIR = rest


SUBDIRS = \
  include $(INTLEMU_SUBDIRS) \
  util \
  nt \
  gnsrecord \
  hello \
  block \
  statistics \
  arm \
  $(TESTING) \
  $(JSON_DIR) \
  $(CURL_DIR) \
  $(REST_DIR) \
  peerinfo \
  $(SQLITE_DIR) \
  $(MYSQL_DIR) \
  $(POSTGRES_DIR) \
  datacache \
  datastore \
  template \
  peerstore \
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
  namecache \
  namestore \
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
  reclaim \
  $(EXP_DIR) \
  integration-tests
