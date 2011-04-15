#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif

if HAVE_ESMTP
if HAVE_OPENSSL
 MONKEY_DIR = monkey
endif
endif
if HAVE_EXPERIMENTAL
 FS_exp = fs
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
  nat \
  transport \
  peerinfo-tool \
  core \
  testing \
  dv \
  dht \
  hostlist \
  topology \
  $(FS_exp) \
  fragmentation \
  mesh \
  vpn \
  chat
