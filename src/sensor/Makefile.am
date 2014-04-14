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

lib_LTLIBRARIES = libgnunetsensor.la

pkgcfgdir= $(prefix)/share/gnunet/config.d/

libexecdir= $(prefix)/lib/gnunet/libexec/

libgnunetsensor_la_SOURCES = \
  sensor_api.c 
libgnunetsensor_la_LIBADD = \
  -lgnunetutil
libgnunetsensor_la_LDFLAGS = \
  $(GNUNET_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = gnunet-sensor

libexec_PROGRAMS = gnunet-service-sensor

check_PROGRAMS = \
 test_sensor_api 

TESTS = $(check_PROGRAMS)

gnunet_service_sensor_SOURCES = \
  gnunet-service-sensor.c
gnunet_service_sensor_LDADD = \
  -lgnunetutil -lgnunetcore -lgnunetdht\
  $(INTLLIBS) 
gnunet_service_sensor_LDFLAGS = \
  $(GNUNET_LDFLAGS)  $(WINFLAGS) -export-dynamic 

gnunet_sensor_SOURCES = \
  gnunet-sensor.c
gnunet_sensor_LDADD = \
  -lgnunetutil \
  libgnunetsensor.la \
  $(INTLLIBS) 
gnunet_sensor_LDFLAGS = \
 $(GNUNET_LDFLAGS) $(WINFLAGS) -export-dynamic 



test_sensor_api_SOURCES = \
 test_sensor_api.c
test_sensor_api_LDADD = \
  $(top_builddir)/src/sensor/libgnunetsensor.la \
  -lgnunetutil
test_sensor_api_LDFLAGS = \
 $(GNUNET_LDFLAGS)  $(WINFLAGS) -export-dynamic
 
 pkgcfg_DATA = sensor.conf 
 
