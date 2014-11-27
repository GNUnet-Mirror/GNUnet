SUBDIRS = .

plugindir = $(libdir)/gnunet

if MINGW
  WINFLAGS = -no-undefined -Wl,--export-all-symbols
endif

AM_CPPFLAGS = \
  $(GNUNET_CPPFLAGS) \
  -I$(top_srcdir)/src/include \
  -I$(top_srcdir)

lib_LTLIBRARIES = \
 libgnunetmicrophone.la \
 libgnunetspeaker.la \
 libgnunetconversation.la

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugin_LTLIBRARIES = \
  libgnunet_plugin_gnsrecord_conversation.la


libgnunet_plugin_gnsrecord_conversation_la_SOURCES = \
  plugin_gnsrecord_conversation.c
libgnunet_plugin_gnsrecord_conversation_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_conversation_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libgnunetmicrophone_la_SOURCES = \
  microphone.c
libgnunetmicrophone_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la
libgnunetmicrophone_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0

libgnunetspeaker_la_SOURCES = \
  speaker.c
libgnunetspeaker_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la
libgnunetspeaker_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


libgnunetconversation_la_SOURCES = \
  conversation_api.c \
  conversation_api_call.c \
  conversation.h
libgnunetconversation_la_LIBADD = \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/util/libgnunetutil.la

libgnunetconversation_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
 gnunet-conversation-test \
 gnunet-conversation

libexec_PROGRAMS = \
  gnunet-service-conversation

check_PROGRAMS = \
 test_conversation_api \
 test_conversation_api_reject \
 test_conversation_api_twocalls

if BUILD_PULSE_HELPERS
AUDIO_HELPER_RECD=gnunet-helper-audio-record
AUDIO_HELPER_PLAY=gnunet-helper-audio-playback
AUDIO_TESTS=$(check_PROGRAMS)
else
if BUILD_GST_HELPERS
AUDIO_HELPER_RECD=gnunet-helper-audio-record
AUDIO_HELPER_PLAY=gnunet-helper-audio-playback
AUDIO_TESTS=$(check_PROGRAMS)
endif
endif

libexec_PROGRAMS += \
  $(AUDIO_HELPER_RECD) \
  $(AUDIO_HELPER_PLAY)

AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
if ENABLE_TEST_RUN
TESTS = $(AUDIO_TESTS)
endif

if BUILD_PULSE_HELPERS
gnunet_helper_audio_record_SOURCES = \
  gnunet-helper-audio-record.c
gnunet_helper_audio_record_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lpulse  -lopus -logg \
  $(INTLLIBS)
gnunet_helper_audio_record_LDFLAGS = \
  $(WINFLAGS)

gnunet_helper_audio_playback_SOURCES = \
  gnunet-helper-audio-playback.c
gnunet_helper_audio_playback_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lpulse -lopus -logg \
  $(INTLLIBS)
gnunet_helper_audio_playback_LDFLAGS = \
  $(WINFLAGS)
else
if BUILD_GST_HELPERS
gnunet_helper_audio_record_SOURCES = \
  gnunet-helper-audio-record-gst.c
gnunet_helper_audio_record_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GST_LIBS) \
  $(INTLLIBS)
gnunet_helper_audio_record_LDFLAGS = \
  $(WINFLAGS) $(GST_LDFLAGS)
gnunet_helper_audio_record_CFLAGS = \
 $(GST_CFLAGS)

gnunet_helper_audio_playback_SOURCES = \
  gnunet-helper-audio-playback-gst.c
gnunet_helper_audio_playback_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GST_LIBS) \
  $(INTLLIBS)
gnunet_helper_audio_playback_LDFLAGS = \
  $(WINFLAGS) $(GST_LDFLAGS)
gnunet_helper_audio_playback_CFLAGS = \
 $(GST_CFLAGS)
endif
endif

gnunet_service_conversation_SOURCES = \
  gnunet-service-conversation.c
gnunet_service_conversation_LDADD = \
  libgnunetconversation.la \
  libgnunetspeaker.la \
  libgnunetmicrophone.la \
  $(top_builddir)/src/cadet/libgnunetcadet.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(INTLLIBS)
gnunet_service_conversation_LDFLAGS = \
  $(WINFLAGS)

gnunet_conversation_SOURCES = \
  gnunet-conversation.c
gnunet_conversation_LDADD = \
  libgnunetmicrophone.la \
  libgnunetspeaker.la \
  libgnunetconversation.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(INTLLIBS)
gnunet_conversation_LDFLAGS = \
 $(WINFLAGS)

gnunet_conversation_test_SOURCES = \
  gnunet-conversation-test.c
gnunet_conversation_test_LDADD = \
  libgnunetmicrophone.la \
  libgnunetspeaker.la \
  $(top_builddir)/src/util/libgnunetutil.la  \
  $(INTLLIBS)
gnunet_conversation_test_LDFLAGS = \
 $(WINFLAGS)


test_conversation_api_SOURCES = \
 test_conversation_api.c
test_conversation_api_LDADD = \
  libgnunetconversation.la \
  libgnunetspeaker.la \
  libgnunetmicrophone.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la
test_conversation_api_LDFLAGS = \
 $(WINFLAGS) -export-dynamic

test_conversation_api_twocalls_SOURCES = \
 test_conversation_api_twocalls.c
test_conversation_api_twocalls_LDADD = \
  libgnunetconversation.la \
  libgnunetspeaker.la \
  libgnunetmicrophone.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la
test_conversation_api_twocalls_LDFLAGS = \
 $(WINFLAGS) -export-dynamic

test_conversation_api_reject_SOURCES = \
 test_conversation_api_reject.c
test_conversation_api_reject_LDADD = \
  libgnunetconversation.la \
  libgnunetspeaker.la \
  libgnunetmicrophone.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la
test_conversation_api_reject_LDFLAGS = \
 $(WINFLAGS) -export-dynamic


 pkgcfg_DATA = conversation.conf

EXTRA_DIST = test_conversation.conf
