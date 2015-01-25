AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  ats.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

noinst_PROGRAMS = \
 gnunet-ats-solver-eval

if HAVE_LIBGLPK
  GN_LIBGLPK = -lglpk
  GN_MLP_LIB = libgnunet_plugin_ats_mlp.la
  GN_MLP_PERF = perf_ats_mlp
  GN_MLP_ADD_ADDRESS = test_ats_solver_add_address_mlp
  GN_MLP_ADD_REQUEST_ADDRESS = test_ats_solver_add_address_and_request_mlp
  GN_MLP_ADD_REQUEST_ADDRESS_DELAYED = test_ats_solver_add_address_and_request_delayed_mlp
  GN_MLP_REQUEST_ADD_ADDRESS = test_ats_solver_request_and_add_address_mlp
  GN_MLP_REQUEST_DELETE_ADDRESS = test_ats_solver_request_and_delete_address_mlp
  GN_MLP_PREFERENCES_ADDRESS = test_ats_solver_preferences_mlp
  GN_MLP_ALTERNATIVE_DELETE_ADDRESS = test_ats_solver_alternative_after_delete_address_mlp
  GN_MLP_SOLVER_PERF = perf_ats_solver_mlp
endif

lib_LTLIBRARIES = libgnunetats.la

plugin_LTLIBRARIES = \
  libgnunet_plugin_ats_proportional.la \
  $(GN_MLP_LIB) \
  libgnunet_plugin_ats_ril.la

gnunet_ats_solver_eval_SOURCES = \
 gnunet-ats-solver-eval.c gnunet-ats-solver-eval.h \
 gnunet-service-ats_normalization.c
gnunet_ats_solver_eval_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunetats.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(LTLIBINTL)

libgnunetats_la_SOURCES = \
  ats_api_scheduling.c \
  ats_api_performance.c
libgnunetats_la_LIBADD = \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(LTLIBINTL)
libgnunetats_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 4:0:0

libgnunet_plugin_ats_proportional_la_SOURCES = \
  plugin_ats_proportional.c
libgnunet_plugin_ats_proportional_la_LIBADD = \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_ats_proportional_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)


if HAVE_LIBGLPK
libgnunet_plugin_ats_mlp_la_SOURCES = \
  plugin_ats_mlp.c
libgnunet_plugin_ats_mlp_la_LIBADD = \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunet_plugin_ats_mlp_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS) $(GN_LIBGLPK)
endif

libgnunet_plugin_ats_ril_la_SOURCES = \
  plugin_ats_ril.c
libgnunet_plugin_ats_ril_la_LIBADD = \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_ats_ril_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)

libexec_PROGRAMS = \
 gnunet-service-ats

gnunet_service_ats_SOURCES = \
 gnunet-service-ats.c gnunet-service-ats.h\
 gnunet-service-ats_addresses.c gnunet-service-ats_addresses.h \
 gnunet-service-ats_normalization.c gnunet-service-ats_normalization.h \
 gnunet-service-ats_performance.c gnunet-service-ats_performance.h \
 gnunet-service-ats_scheduling.c gnunet-service-ats_scheduling.h \
 gnunet-service-ats_reservations.c gnunet-service-ats_reservations.h
gnunet_service_ats_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetats.la \
  $(GN_LIBINTL)

if HAVE_TESTING
TESTING_TESTS = \
 test_ats_api_scheduling_init \
 test_ats_api_scheduling_add_address \
 test_ats_api_scheduling_add_address_duplicate \
 test_ats_api_scheduling_add_address_inbound \
 test_ats_api_scheduling_destroy_address \
 test_ats_api_scheduling_add_session \
 test_ats_api_delayed_service_scheduling_add_address \
 test_ats_api_performance_list_all_addresses \
 test_ats_api_delayed_service_performance_list_all_addresses \
 test_ats_api_performance_list_peer_addresses \
 test_ats_api_performance_list_all_addresses_active \
 test_ats_api_performance_monitor \
 test_ats_api_delayed_service_performance_monitor \
 test_ats_api_performance_monitor_initial_callback \
 test_ats_solver_add_address_proportional \
 test_ats_solver_add_address_and_request_proportional \
 test_ats_solver_add_address_and_request_delayed_proportional\
 test_ats_solver_request_and_add_address_proportional \
 test_ats_solver_request_and_delete_address_proportional \
 test_ats_solver_alternative_after_delete_address_proportional \
 test_ats_solver_preferences_proportional \
 test_ats_solver_preferences_ril \
 $(GN_MLP_ADD_ADDRESS) \
 $(GN_MLP_ADD_REQUEST_ADDRESS) \
 $(GN_MLP_ADD_REQUEST_ADDRESS_DELAYED) \
 $(GN_MLP_REQUEST_ADD_ADDRESS) \
 $(GN_MLP_REQUEST_DELETE_ADDRESS) \
 $(GN_MLP_ALTERNATIVE_DELETE_ADDRESS) \
 $(GN_MLP_PREFERENCES_ADDRESS) \
 test_ats_solver_add_address_ril \
 test_ats_solver_add_address_and_request_ril \
  test_ats_solver_add_address_and_request_delayed_ril \
 test_ats_solver_request_and_add_address_ril \
 test_ats_solver_request_and_delete_address_ril \
 test_ats_solver_alternative_after_delete_address_ril \
 perf_ats_solver_proportional \
 $(GN_MLP_SOLVER_PERF) \
 perf_ats_solver_ril
endif

check_PROGRAMS = \
 $(TESTING_TESTS)

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

# scheduling API tests

test_ats_api_scheduling_init_SOURCES = \
 test_ats_api_scheduling_init.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_api_scheduling_init_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_api_scheduling_add_address_SOURCES = \
 test_ats_api_scheduling_add_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_api_scheduling_add_address_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_api_delayed_service_scheduling_add_address_SOURCES = \
 test_ats_api_delayed_service_scheduling_add_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_api_delayed_service_scheduling_add_address_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_api_scheduling_add_address_inbound_SOURCES = \
 test_ats_api_scheduling_add_address_inbound.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_api_scheduling_add_address_inbound_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_api_scheduling_add_address_duplicate_SOURCES = \
 test_ats_api_scheduling_add_address_duplicate.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_api_scheduling_add_address_duplicate_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_api_scheduling_destroy_address_SOURCES = \
 test_ats_api_scheduling_destroy_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_api_scheduling_destroy_address_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_api_scheduling_add_session_SOURCES = \
 test_ats_api_scheduling_add_session.c test_ats_api_common.c
test_ats_api_scheduling_add_session_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la

# performance API tests

test_ats_api_performance_list_all_addresses_SOURCES = \
 test_ats_api_performance_list_all_addresses.c
test_ats_api_performance_list_all_addresses_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_api_delayed_service_performance_list_all_addresses_SOURCES = \
 test_ats_api_delayed_service_performance_list_all_addresses.c
test_ats_api_delayed_service_performance_list_all_addresses_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_api_performance_list_peer_addresses_SOURCES = \
 test_ats_api_performance_list_peer_addresses.c
test_ats_api_performance_list_peer_addresses_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_api_performance_list_all_addresses_active_SOURCES = \
 test_ats_api_performance_list_all_addresses_active.c
test_ats_api_performance_list_all_addresses_active_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_api_performance_monitor_SOURCES = \
 test_ats_api_performance_monitor.c
test_ats_api_performance_monitor_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_api_delayed_service_performance_monitor_SOURCES = \
 test_ats_api_delayed_service_performance_monitor.c
test_ats_api_delayed_service_performance_monitor_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la



test_ats_api_performance_monitor_initial_callback_SOURCES = \
 test_ats_api_performance_monitor_initial_callback.c
test_ats_api_performance_monitor_initial_callback_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

# solver tests
test_ats_solver_add_address_proportional_SOURCES = \
 test_ats_solver_add_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_add_address_proportional_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

if HAVE_LIBGLPK
test_ats_solver_add_address_mlp_SOURCES = \
 test_ats_solver_add_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_add_address_mlp_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
endif

test_ats_solver_add_address_ril_SOURCES = \
 test_ats_solver_add_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_add_address_ril_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_solver_add_address_and_request_proportional_SOURCES = \
 test_ats_solver_add_address_and_request.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_add_address_and_request_proportional_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_solver_add_address_and_request_delayed_proportional_SOURCES = \
 test_ats_solver_add_address_and_request.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_add_address_and_request_delayed_proportional_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_solver_add_address_and_request_delayed_ril_SOURCES = \
 test_ats_solver_add_address_and_request.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_add_address_and_request_delayed_ril_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

if HAVE_LIBGLPK
test_ats_solver_add_address_and_request_mlp_SOURCES = \
 test_ats_solver_add_address_and_request.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_add_address_and_request_mlp_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
endif

test_ats_solver_add_address_and_request_delayed_mlp_SOURCES = \
 test_ats_solver_add_address_and_request.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_add_address_and_request_delayed_mlp_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_solver_add_address_and_request_ril_SOURCES = \
 test_ats_solver_add_address_and_request.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_add_address_and_request_ril_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la


test_ats_solver_request_and_add_address_proportional_SOURCES = \
 test_ats_solver_request_and_add_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_request_and_add_address_proportional_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

if HAVE_LIBGLPK
test_ats_solver_request_and_add_address_mlp_SOURCES = \
 test_ats_solver_request_and_add_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_request_and_add_address_mlp_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
endif

test_ats_solver_request_and_add_address_ril_SOURCES = \
 test_ats_solver_request_and_add_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_request_and_add_address_ril_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la


test_ats_solver_request_and_delete_address_proportional_SOURCES = \
 test_ats_solver_request_and_delete_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_request_and_delete_address_proportional_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la

if HAVE_LIBGLPK
test_ats_solver_request_and_delete_address_mlp_SOURCES = \
 test_ats_solver_request_and_delete_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_request_and_delete_address_mlp_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la
endif

test_ats_solver_request_and_delete_address_ril_SOURCES = \
 test_ats_solver_request_and_delete_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_request_and_delete_address_ril_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la


test_ats_solver_alternative_after_delete_address_proportional_SOURCES = \
 test_ats_solver_alternative_after_delete_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_alternative_after_delete_address_proportional_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_solver_preferences_proportional_SOURCES = \
 test_ats_solver_preferences.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_preferences_proportional_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la

if HAVE_LIBGLPK
test_ats_solver_alternative_after_delete_address_mlp_SOURCES = \
 test_ats_solver_alternative_after_delete_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_alternative_after_delete_address_mlp_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_solver_preferences_mlp_SOURCES = \
 test_ats_solver_preferences.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_preferences_mlp_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
endif

test_ats_solver_alternative_after_delete_address_ril_SOURCES = \
 test_ats_solver_alternative_after_delete_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_alternative_after_delete_address_ril_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

#perf_ats_mlp_SOURCES = \
#  $(GN_MLP_SRC) perf_ats_mlp.c test_ats_api_common.c gnunet-service-ats_normalization.c
#perf_ats_mlp_LDADD = \
#  $(GN_LIBGLPK) \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/statistics/libgnunetstatistics.la \
#  libgnunetats.la

perf_ats_solver_mlp_SOURCES = \
  perf_ats_solver.c test_ats_api_common.c gnunet-service-ats_normalization.c
perf_ats_solver_mlp_LDADD = \
  $(GN_LIBGLPK) \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  libgnunetats.la

perf_ats_solver_proportional_SOURCES = \
  perf_ats_solver.c test_ats_api_common.c gnunet-service-ats_normalization.c
perf_ats_solver_proportional_LDADD = \
  $(GN_LIBGLPK) \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  libgnunetats.la

perf_ats_solver_ril_SOURCES = \
  perf_ats_solver.c test_ats_api_common.c gnunet-service-ats_normalization.c
perf_ats_solver_ril_LDADD = \
  $(GN_LIBGLPK) \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  libgnunetats.la

test_ats_solver_preferences_ril_SOURCES = \
 test_ats_solver_preferences.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_preferences_ril_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

EXTRA_DIST = \
  ats.h \
  test_delay \
  test_ats_api.conf \
  test_ats_api_delayed.conf \
  test_ats_mlp.conf \
  test_ats_solver_default.conf \
  test_ats_solver_proportional.conf \
  test_ats_solver_proportional.conf \
  test_ats_solver_mlp.conf \
  test_ats_solver_delayed_mlp.conf \
  test_ats_solver_ril.conf \
  test_ats_solver_delayed_ril.conf \
  perf_ats_solver_mlp.conf \
  test_ats_solver_delayed_mlp.conf \
  perf_ats_solver_proportional.conf \
  perf_ats_solver_ril.conf \
  perf_ats_solver.conf
