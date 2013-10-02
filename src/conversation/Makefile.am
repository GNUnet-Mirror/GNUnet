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

lib_LTLIBRARIES = libgnunetconversation.la

pkgcfgdir= $(prefix)/share/gnunet/config.d/

libexecdir= $(prefix)/lib/gnunet/libexec/

libgnunetconversation_la_SOURCES = \
  conversation_api.c 
libgnunetconversation_la_LIBADD = \
  -lgnunetutil -lgnunetnamestore -lgnunetgns
libgnunetconversation_la_LDFLAGS = \
  $(GNUNET_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = gnunet-conversation

libexec_PROGRAMS = \
  gnunet-service-conversation 

if HAVE_PULSE
if HAVE_OPUS
libexec_PROGRAMS +=
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
  $(GNUNET_LDFLAGS)  $(WINFLAGS) -export-dynamic

gnunet_helper_audio_playback_SOURCES = \
  gnunet-helper-audio-playback.c
gnunet_helper_audio_playback_LDADD = \
  -lgnunetutil \
  -lpulse -lopus\
  $(INTLLIBS) 
gnunet_helper_audio_playback_LDFLAGS = \
  $(GNUNET_LDFLAGS)  $(WINFLAGS) -export-dynamic  

gnunet_service_conversation_SOURCES = \
  gnunet-service-conversation.c
gnunet_service_conversation_LDADD = \
  -lgnunetutil -lgnunetmesh -lgnunetnamestore -lgnunetgns\
    $(INTLLIBS) 
gnunet_service_conversation_LDFLAGS = \
  $(GNUNET_LDFLAGS)  $(WINFLAGS) -export-dynamic 

gnunet_conversation_SOURCES = \
  gnunet-conversation.c
gnunet_conversation_LDADD = \
  -lgnunetutil -lgnunetconversation \
  $(INTLLIBS) 
gnunet_conversation_LDFLAGS = \
 $(GNUNET_LDFLAGS) $(WINFLAGS) -export-dynamic 



test_conversation_api_SOURCES = \
 test_conversation_api.c
test_conversation_api_LDADD = \
  $(top_builddir)/src/conversation/libgnunetconversation.la \
  -lgnunetutil
test_conversation_api_LDFLAGS = \
 $(GNUNET_LDFLAGS)  $(WINFLAGS) -export-dynamic

 pkgcfg_DATA = conversation.conf 
