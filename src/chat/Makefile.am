INCLUDES = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
  chat.conf

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
gnunet_chat_DEPENDENCIES = \
  libgnunetchat.la

check_PROGRAMS = \
 test_chat \
 test_chat_acknowledgement \
 test_chat_anonymous \
 test_chat_authentication \
 test_chat_p2p \
 test_chat_acknowledgement_p2p \
 test_chat_anonymous_p2p \
 test_chat_authentication_p2p \
 test_chat_private \
 test_chat_private_p2p

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_chat_SOURCES = \
 test_chat.c
test_chat_LDADD = \
  $(top_builddir)/src/chat/libgnunetchat.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_chat_acknowledgement_SOURCES = \
 test_chat.c
test_chat_acknowledgement_LDADD = \
  $(top_builddir)/src/chat/libgnunetchat.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_chat_anonymous_SOURCES = \
 test_chat.c
test_chat_anonymous_LDADD = \
  $(top_builddir)/src/chat/libgnunetchat.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_chat_authentication_SOURCES = \
 test_chat.c
test_chat_authentication_LDADD = \
  $(top_builddir)/src/chat/libgnunetchat.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_chat_p2p_SOURCES = \
 test_chat.c
test_chat_p2p_LDADD = \
  $(top_builddir)/src/chat/libgnunetchat.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_chat_acknowledgement_p2p_SOURCES = \
 test_chat.c
test_chat_acknowledgement_p2p_LDADD = \
  $(top_builddir)/src/chat/libgnunetchat.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_chat_anonymous_p2p_SOURCES = \
 test_chat.c
test_chat_anonymous_p2p_LDADD = \
  $(top_builddir)/src/chat/libgnunetchat.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_chat_authentication_p2p_SOURCES = \
 test_chat.c
test_chat_authentication_p2p_LDADD = \
  $(top_builddir)/src/chat/libgnunetchat.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_chat_private_SOURCES = \
 test_chat_private.c
test_chat_private_LDADD = \
  $(top_builddir)/src/chat/libgnunetchat.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_chat_private_p2p_SOURCES = \
 test_chat_private.c
test_chat_private_p2p_LDADD = \
  $(top_builddir)/src/chat/libgnunetchat.la \
  $(top_builddir)/src/util/libgnunetutil.la

EXTRA_DIST = \
  test_chat_data.conf \
  test_chat_peer1.conf \
  test_chat_peer2.conf \
  test_chat_peer3.conf
