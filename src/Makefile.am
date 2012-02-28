#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif

if HAVE_EXPERIMENTAL
 EXP_DIR = chat dv gns stream
endif

if LINUX
# All of these currently only work on GNU/Linux
 LINUX_DIR = dns exit vpn pt
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
  nse \
  dht \
  hostlist \
  topology \
  fs \
  mesh \
  $(LINUX_DIR) \
  integration-tests \
  $(EXP_DIR) 
