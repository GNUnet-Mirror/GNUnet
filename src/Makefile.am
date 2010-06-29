#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif

if !MINGW
 NAT_DIR = nat
endif

if HAVE_ESMTP
 MONKEY_DIR = monkey
endif

SUBDIRS = \
  include $(INTLEMU_SUBDIRS) \
  util \
  block \
  statistics \
  arm \
  $(MONKEY_DIR) \
  hello \
  peerinfo \
  datacache \
  datastore \
  template \
  transport \
  peerinfo-tool \
  core \
  testing \
  dv \
  hostlist \
  topology \
  $(NAT_DIR) \
  fs
