#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif

if !MINGW
 NAT_DIR = nat
endif

if HAVE_ESMTP
if HAVE_OPENSSL
 MONKEY_DIR = monkey
endif
endif

SUBDIRS = \
  include $(INTLEMU_SUBDIRS) \
  util \
  hello \
  block \
  statistics \
  arm \
  $(MONKEY_DIR) \
  peerinfo \
  datacache \
  datastore \
  template \
  transport \
  peerinfo-tool \
  core \
  testing \
  dv \
  dht \
  hostlist \
  topology \
  $(NAT_DIR) \
  fs \
  fragmentation \
  vpn
