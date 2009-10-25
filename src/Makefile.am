#if WANT_FRAMEWORK
#  INTLEMU_SUBDIRS = intlemu
#endif


if HAVE_MHD
 HOSTLIST_DIR = hostlist
endif

SUBDIRS = \
  include $(INTLEMU_SUBDIRS) \
  util \
  arm \
  fragmentation \
  hello \
  nat \
  peerinfo \
  statistics \
  datacache \
  datastore \
  template \
  transport \
  core \
  testing \
  $(HOSTLIST_DIR) \
  topology \
  fs

