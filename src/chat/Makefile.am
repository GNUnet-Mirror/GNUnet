INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = libgnunetchat.la

libgnunetchat_la_SOURCES = \
  chat.c chat.h

libgnunetchat_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la

libgnunetchat_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0

bin_PROGRAMS = \
 gnunet-service-chat \
 gnunet-chat

gnunet_service_chat_SOURCES = \
 gnunet-service-chat.c         
gnunet_service_chat_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_chat_SOURCES = \
 gnunet-chat.c         
gnunet_chat_LDADD = \
  $(top_builddir)/src/chat/libgnunetchat.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
