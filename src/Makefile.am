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
  arm \
  fragmentation \
  hello \
  peerinfo \
  statistics \
  datacache \
  datastore \
  template \
  transport \
  core \
  $(HOSTLIST_DIR) \
  topology \
  fs \
  $(NAT_DIR) \
  testing

