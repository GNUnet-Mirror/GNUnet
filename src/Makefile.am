#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif


if HAVE_MHD
 HOSTLIST_DIR = hostlist
endif

if !MINGW
 NAT_DIR = nat
endif

SUBDIRS = \
  include $(INTLEMU_SUBDIRS) \
  util \
  statistics \
  arm \
  hello \
  peerinfo \
  datacache \
  datastore \
  template \
  transport \
  core \
  testing \
  $(HOSTLIST_DIR) \
  topology \
  $(NAT_DIR) \
  fs
