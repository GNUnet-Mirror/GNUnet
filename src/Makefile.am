#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif

if !MINGW
 NAT_DIR = nat
endif

SUBDIRS = \
  include $(INTLEMU_SUBDIRS) \
  util \
  block \
  statistics \
  arm \
  hello \
  peerinfo \
  datacache \
  datastore \
  template \
  transport \
  peerinfo-tool \
  core \
  testing \
  hostlist \
  topology \
  $(NAT_DIR) \
  fs \
  migration
