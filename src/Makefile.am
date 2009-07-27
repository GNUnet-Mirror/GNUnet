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
  peerinfo \
  resolver \
  statistics \
  datacache \
  datastore \
  testing \
  template \
  transport \
  core \
  $(HOSTLIST_DIR) \
  topology 

