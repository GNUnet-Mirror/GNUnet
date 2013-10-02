SUBDIRS = .

INCLUDES = \
  -I$(top_srcdir)/src/include \
  -I$(top_srcdir)

AM_CPPFLAGS = \
  $(GNUNET_CPPFLAGS)

# Set this variable if you are using GNUNET libraries for all programs and
# libraries. You don't then need to target-specific _LDFLAGS with GNUNET_LDFLAGS
# AM_LDFLAGS = \
#   $(GNUNET_LDFLAGS) \
#   $(WINFLAGS) \
#   -export-dynamic

lib_LTLIBRARIES = \
 libgnunetmicrophone.la \
 libgnunetspeaker.la \
 libgnunetconversation.la

pkgcfgdir= $(prefix)/share/gnunet/config.d/

libexecdir= $(prefix)/lib/gnunet/libexec/

libgnunetmicrophone_la_SOURCES = \
  microphone.c 
libgnunetmicrophone_la_LIBADD = \
  -lgnunetutil
libgnunetmicrophone_la_LDFLAGS = \
  $(GNUNET_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0

libgnunetspeaker_la_SOURCES = \
  speaker.c 
libgnunetspeaker_la_LIBADD = \
  -lgnunetutil
libgnunetspeaker_la_LDFLAGS = \
  $(GNUNET_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


libgnunetconversation_la_SOURCES = \
  conversation_api.c \
  conversation_api2.c 
libgnunetconversation_la_LIBADD = \
  libgnunetmicrophone.la \
  libgnunetspeaker.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/util/libgnunetutil.la 

libgnunetconversation_la_LDFLAGS = \
  $(GNUNET_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
 gnunet-conversation-test \
 gnunet-conversation

libexec_PROGRAMS = \
  gnunet-service-conversation 

if HAVE_PULSE
if HAVE_OPUS
libexec_PROGRAMS += \
  gnunet-helper-audio-record \
  gnunet-helper-audio-playback
endif
endif



check_PROGRAMS = \
 test_conversation_api 

TESTS = $(check_PROGRAMS)


gnunet_helper_audio_record_SOURCES = \
  gnunet-helper-audio-record.c
gnunet_helper_audio_record_LDADD = \
  -lgnunetutil \
  -lpulse  -lopus\
  $(INTLLIBS) 
gnunet_helper_audio_record_LDFLAGS = \
  $(GNUNET_LDFLAGS)  $(WINFLAGS) 

gnunet_helper_audio_playback_SOURCES = \
  gnunet-helper-audio-playback.c
gnunet_helper_audio_playback_LDADD = \
  -lgnunetutil \
  -lpulse -lopus\
  $(INTLLIBS) 
gnunet_helper_audio_playback_LDFLAGS = \
  $(GNUNET_LDFLAGS)  $(WINFLAGS) 

gnunet_service_conversation_SOURCES = \
  gnunet-service-conversation.c
gnunet_service_conversation_LDADD = \
  -lgnunetutil -lgnunetmesh -lgnunetnamestore -lgnunetgns\
    $(INTLLIBS) 
gnunet_service_conversation_LDFLAGS = \
  $(GNUNET_LDFLAGS)  $(WINFLAGS) 

gnunet_conversation_SOURCES = \
  gnunet-conversation.c
gnunet_conversation_LDADD = \
  -lgnunetutil -lgnunetconversation \
  $(INTLLIBS) 
gnunet_conversation_LDFLAGS = \
 $(GNUNET_LDFLAGS) $(WINFLAGS) 

gnunet_conversation_test_SOURCES = \
  gnunet-conversation-test.c
gnunet_conversation_test_LDADD = \
  libgnunetmicrophone.la \
  libgnunetspeaker.la \
  $(top_builddir)/src/util/libgnunetutil.la  \
  $(INTLLIBS) 
gnunet_conversation_test_LDFLAGS = \
 $(GNUNET_LDFLAGS) $(WINFLAGS) 


test_conversation_api_SOURCES = \
 test_conversation_api.c
test_conversation_api_LDADD = \
  $(top_builddir)/src/conversation/libgnunetconversation.la \
  -lgnunetutil
test_conversation_api_LDFLAGS = \
 $(GNUNET_LDFLAGS)  $(WINFLAGS) -export-dynamic

 pkgcfg_DATA = conversation.conf 
