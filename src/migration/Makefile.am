INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

bin_PROGRAMS = \
 gnunet-daemon-migration

gnunet_daemon_migration_SOURCES = \
 gnunet-daemon-migration.c 
gnunet_daemon_migration_LDADD = \
  $(top_builddir)/src/datastore/libgnunetdatastore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

check_PROGRAMS = test_gnunet_daemon_migration 
#TESTS = $(check_PROGRAMS)

test_gnunet_daemon_migration_SOURCES = \
 test_gnunet_daemon_migration.c
test_gnunet_daemon_migration_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  

EXTRA_DIST = \
 test_gnunet_daemon_migration_data.conf 
