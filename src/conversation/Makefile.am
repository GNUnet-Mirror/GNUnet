# This Makefile.am is in the public domain
SUBDIRS = .

plugindir = $(libdir)/gnunet

AM_CPPFLAGS = \
  $(GNUNET_CPPFLAGS) \
  -I$(top_srcdir)/src/include \
  -I$(top_srcdir)


if BUILD_CONVERSATION
lib_LTLIBRARIES = \
 libgnunetmicrophone.la \
 libgnunetspeaker.la \
 libgnunetconversation.la

bin_PROGRAMS = \
 gnunet-conversation-test \
 gnunet-conversation

libexec_PROGRAMS = \
  gnunet-service-conversation

check_PROGRAMS = \
 test_conversation_api \
 test_conversation_api_reject \
 test_conversation_api_twocalls

pkgcfg_DATA = conversation.conf
endif

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
  $(GN_LIB_LDFLAGS)   \
  -version-info 0:0:0

libgnunetspeaker_la_SOURCES = \
  speaker.c
libgnunetspeaker_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la
libgnunetspeaker_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
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
  $(GN_LIB_LDFLAGS)   \
  -version-info 0:0:0


if BUILD_PULSE_HELPERS
AUDIO_HELPER_RECD=gnunet-helper-audio-record
AUDIO_HELPER_PLAY=gnunet-helper-audio-playback
AUDIO_TESTS=$(check_PROGRAMS)
else
if BUILD_GST_HELPERS
AUDIO_HELPER_RECD=gnunet-helper-audio-record
AUDIO_HELPER_PLAY=gnunet-helper-audio-playback
AUDIO_TESTS=$(check_PROGRAMS)
else
if BUILD_EXPERIMENTAL_HELPERS
AUDIO_HELPER_RECD=gnunet-helper-audio-record
AUDIO_HELPER_PLAY=gnunet-helper-audio-playback
AUDIO_TESTS=$(check_PROGRAMS)
endif
endif
endif

if BUILD_CONVERSATION
libexec_PROGRAMS += \
  $(AUDIO_HELPER_RECD) \
  $(AUDIO_HELPER_PLAY)
endif

AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
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
#gnunet_helper_audio_record_LDFLAGS = \
#  

gnunet_helper_audio_playback_SOURCES = \
  gnunet-helper-audio-playback.c
gnunet_helper_audio_playback_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lpulse -lopus -logg \
  $(INTLLIBS)
#gnunet_helper_audio_playback_LDFLAGS = \
#  
else
if BUILD_GST_HELPERS
gnunet_helper_audio_record_SOURCES = \
  gnunet-helper-audio-record-gst.c
gnunet_helper_audio_record_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GST_LIBS) \
  $(INTLLIBS)
gnunet_helper_audio_record_LDFLAGS = \
   $(GST_LDFLAGS)
gnunet_helper_audio_record_CFLAGS = \
 $(GST_CFLAGS)

gnunet_helper_audio_playback_SOURCES = \
    gnunet-helper-audio-playback-gst.c
gnunet_helper_audio_playback_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GST_LIBS) \
  $(INTLLIBS)
gnunet_helper_audio_playback_LDFLAGS = \
   $(GST_LDFLAGS)
gnunet_helper_audio_playback_CFLAGS = \
 $(GST_CFLAGS) -DIS_SPEAKER
else
if BUILD_EXPERIMENTAL_HELPERS
gnunet_helper_audio_record_SOURCES = \
  gnunet_gst_test.c gnunet_gst.c
gnunet_helper_audio_record_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GST_LIBS) \
  $(INTLLIBS)
gnunet_helper_audio_record_LDFLAGS = \
   $(GST_LDFLAGS)
gnunet_helper_audio_record_CFLAGS = \
 $(GST_CFLAGS) -DIS_MIC

gnunet_helper_audio_playback_SOURCES = \
    gnunet_gst_test.c gnunet_gst.c
gnunet_helper_audio_playback_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GST_LIBS) \
  $(INTLLIBS)
gnunet_helper_audio_playback_LDFLAGS = \
   $(GST_LDFLAGS)
gnunet_helper_audio_playback_CFLAGS = \
 $(GST_CFLAGS) -DIS_SPEAKER
endif
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
#gnunet_service_conversation_LDFLAGS = \
#  

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
#gnunet_conversation_LDFLAGS = \
# 

gnunet_conversation_test_SOURCES = \
  gnunet-conversation-test.c
gnunet_conversation_test_LDADD = \
  libgnunetmicrophone.la \
  libgnunetspeaker.la \
  $(top_builddir)/src/util/libgnunetutil.la  \
  $(INTLLIBS)
#gnunet_conversation_test_LDFLAGS = \
# 


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
  -export-dynamic

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
  -export-dynamic

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
  -export-dynamic



EXTRA_DIST = test_conversation.conf
