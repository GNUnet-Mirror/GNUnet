#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif

if HAVE_ESMTP
if HAVE_OPENSSL
if HAVE_EXPERIMENTAL
 MONKEY_DIR = monkey
endif
endif
endif

if HAVE_EXPERIMENTAL
 EXP_DIR = fragmentation mesh vpn chat
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
  fs \
  $(EXP_DIR)
