#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif

if HAVE_EXPERIMENTAL
 EXP_DIR = chat dv stream regex
endif

if LINUX
# All of these currently only work on GNU/Linux
 LINUX_DIR = dns gns exit vpn pt
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
  peerinfo \
  $(MYSQL_DIR) \
  $(POSTGRES_DIR) \
  datacache \
  datastore \
  namestore \
  template \
  ats \
  nat \
  fragmentation \
  transport \
  peerinfo-tool \
  core \
  testing \
  testbed \
  nse \
  dht \
  hostlist \
  topology \
  fs \
  mesh \
  lockmanager \
  $(LINUX_DIR) \
  integration-tests \
  $(EXP_DIR) 
