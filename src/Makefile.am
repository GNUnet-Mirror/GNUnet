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
  datastore \
  fragmentation \
  hello \
  peerinfo \
  resolver \
  statistics \
  template \
  transport \
  core \
  $(HOSTLIST_DIR) \
  topology 

