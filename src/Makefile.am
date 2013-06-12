#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif

if HAVE_LIBIDN
 DNS = dns
 EXIT = exit
 PT = pt
else
 DNS =
 EXIT =
 PT =
endif

if HAVE_EXPERIMENTAL
 EXP_DIR = gns set dv consensus experimentation
endif

if LINUX
# All of these currently only work on GNU/Linux
 LINUX_DIR = $(DNS) $(EXIT) vpn $(PT)
endif
if MINGW
 MINGW_DIR = $(DNS) vpn $(EXIT)
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
  testing \
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
  ats-tool \
  peerinfo-tool \
  core \
  testbed \
  nse \
  dht \
  hostlist \
  topology \
  regex \
  mesh \
  lockmanager \
  stream \ 
  fs \
  $(LINUX_DIR) \
  $(MINGW_DIR) \
  integration-tests \
  $(EXP_DIR) 
