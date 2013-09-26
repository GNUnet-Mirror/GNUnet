AM_CPPFLAGS = -I$(top_srcdir)/src/include

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

if HAVE_LIBGLPK
  GN_LIBGLPK = -lglpk
  GN_MLP_SRC = gnunet-service-ats-solver_mlp.c gnunet-service-ats-solver_mlp.h
  GN_MLP_TEST = test_ats_mlp
  GN_MLP_TEST_UPDATE = test_ats_mlp_update
  GN_MLP_TEST_AVG = test_ats_mlp_averaging
  GN_MLP_PERF = perf_ats_mlp
  GN_MLP_ADD_ADDRESS = test_ats_solver_add_address_mlp
  GN_MLP_ADD_REQUEST_ADDRESS = test_ats_solver_add_address_and_request_mlp
  GN_MLP_REQUEST_ADD_ADDRESS = test_ats_solver_request_and_add_address_mlp
  GN_MLP_REQUEST_DELETE_ADDRESS = test_ats_solver_request_and_delete_address_mlp
endif

lib_LTLIBRARIES = libgnunetats.la

libgnunetats_la_SOURCES = \
  ats_api_scheduling.c \
  ats_api_performance.c 

libgnunetats_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(LTLIBINTL)

libgnunetats_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
  -version-info 4:0:0


libexec_PROGRAMS = \
 gnunet-service-ats

gnunet_service_ats_SOURCES = \
 gnunet-service-ats.c gnunet-service-ats.h\
 gnunet-service-ats_addresses.c gnunet-service-ats_addresses.h \
 gnunet-service-ats_normalization.c gnunet-service-ats_normalization.h \
 gnunet-service-ats-solver_proportional.c gnunet-service-ats-solver_proportional.h \
 $(GN_MLP_SRC) \
 gnunet-service-ats-solver_ril.c gnunet-service-ats-solver_ril.h \
 gnunet-service-ats_performance.c gnunet-service-ats_performance.h \
 gnunet-service-ats_scheduling.c gnunet-service-ats_scheduling.h \
 gnunet-service-ats_reservations.c gnunet-service-ats_reservations.h
gnunet_service_ats_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetats.la \
  $(GN_LIBGLPK) \
  $(GN_LIBINTL)
gnunet_service_ats_DEPENDENCIES = \
  libgnunetats.la

if HAVE_TESTING
TESTING_TESTS = \
 test_ats_api_scheduling_init \
 test_ats_api_scheduling_add_address \
 test_ats_api_scheduling_add_address_duplicate \
 test_ats_api_scheduling_add_address_inbound \
 test_ats_api_scheduling_destroy_address \
 test_ats_api_scheduling_destroy_address_twice \
 test_ats_api_scheduling_add_session \
 test_ats_api_scheduling_destroy_session \
 test_ats_api_performance_list_all_addresses \
 test_ats_api_performance_list_peer_addresses \
 test_ats_api_performance_list_all_addresses_active \
 test_ats_api_performance_monitor \
 test_ats_api_performance_monitor_initial_callback \
 test_ats_solver_add_address_proportional \
 $(GN_MLP_ADD_ADDRESS) \
 test_ats_solver_add_address_ril \
 test_ats_solver_add_address_and_request_proportional \
 $(GN_MLP_ADD_REQUEST_ADDRESS) \
 test_ats_solver_add_address_and_request_ril \
 test_ats_solver_request_and_add_address_proportional \
 $(GN_MLP_REQUEST_ADD_ADDRESS) \
 test_ats_solver_request_and_add_address_ril \
 test_ats_solver_request_and_delete_address_proportional \
 $(GN_MLP_REQUEST_DELETE_ADDRESS) \
 test_ats_solver_request_and_delete_address_ril  
# test_ats_api_scheduling_min_bw
# test_ats_api_scheduling_check_min_bw_alt
# test_ats_api_scheduling_update_address
# test_ats_api_scheduling_destroy_inbound_connection
# test_ats_api_scheduling_block_and_reset
# test_ats_normalization_update_quality
# test_ats_change_preference
# test_ats_simplistic
# test_ats_simplistic_switch_networks
# test_ats_simplistic_change_preference
# test_ats_api_performance_address_info
# test_ats_api_performance_feedback
endif

check_PROGRAMS = \
 $(TESTING_TESTS)
# $(GN_MLP_TEST) $(GN_MLP_PERF) $(GN_MLP_TEST_UPDATE)
# $(GN_MLP_TEST_AVG)

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

# scheduling API tests

test_ats_api_scheduling_init_SOURCES = \
 test_ats_api_scheduling_init.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_api_scheduling_init_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la      

test_ats_api_scheduling_add_address_SOURCES = \
 test_ats_api_scheduling_add_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_api_scheduling_add_address_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la    

test_ats_api_scheduling_add_address_inbound_SOURCES = \
 test_ats_api_scheduling_add_address_inbound.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_api_scheduling_add_address_inbound_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la    

test_ats_api_scheduling_add_address_duplicate_SOURCES = \
 test_ats_api_scheduling_add_address_duplicate.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_api_scheduling_add_address_duplicate_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la    

test_ats_api_scheduling_destroy_address_SOURCES = \
 test_ats_api_scheduling_destroy_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_api_scheduling_destroy_address_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la    

test_ats_api_scheduling_destroy_address_twice_SOURCES = \
 test_ats_api_scheduling_destroy_address_twice.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_api_scheduling_destroy_address_twice_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la    

test_ats_api_scheduling_add_session_SOURCES = \
 test_ats_api_scheduling_add_session.c test_ats_api_common.c
test_ats_api_scheduling_add_session_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la  

test_ats_api_scheduling_destroy_session_SOURCES = \
 test_ats_api_scheduling_destroy_session.c test_ats_api_common.c
test_ats_api_scheduling_destroy_session_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la  

# performance API tests

test_ats_api_performance_list_all_addresses_SOURCES = \
 test_ats_api_performance_list_all_addresses.c
test_ats_api_performance_list_all_addresses_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_api_performance_list_peer_addresses_SOURCES = \
 test_ats_api_performance_list_peer_addresses.c
test_ats_api_performance_list_peer_addresses_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
	
test_ats_api_performance_list_all_addresses_active_SOURCES = \
 test_ats_api_performance_list_all_addresses_active.c
test_ats_api_performance_list_all_addresses_active_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_api_performance_monitor_SOURCES = \
 test_ats_api_performance_monitor.c
test_ats_api_performance_monitor_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
	
test_ats_api_performance_monitor_initial_callback_SOURCES = \
 test_ats_api_performance_monitor_initial_callback.c	
test_ats_api_performance_monitor_initial_callback_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
	
# solver tests
test_ats_solver_add_address_proportional_SOURCES = \
 test_ats_solver_add_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_add_address_proportional_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
	
if HAVE_LIBGLPK	
test_ats_solver_add_address_mlp_SOURCES = \
 test_ats_solver_add_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_add_address_mlp_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
endif  
			
test_ats_solver_add_address_ril_SOURCES = \
 test_ats_solver_add_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_add_address_ril_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
			
test_ats_solver_add_address_and_request_proportional_SOURCES = \
 test_ats_solver_add_address_and_request.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_add_address_and_request_proportional_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
	
if HAVE_LIBGLPK	
test_ats_solver_add_address_and_request_mlp_SOURCES = \
 test_ats_solver_add_address_and_request.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_add_address_and_request_mlp_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
endif  
			
test_ats_solver_add_address_and_request_ril_SOURCES = \
 test_ats_solver_add_address_and_request.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_add_address_and_request_ril_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la


test_ats_solver_request_and_add_address_proportional_SOURCES = \
 test_ats_solver_request_and_add_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_request_and_add_address_proportional_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
	
if HAVE_LIBGLPK	
test_ats_solver_request_and_add_address_mlp_SOURCES = \
 test_ats_solver_request_and_add_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_request_and_add_address_mlp_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
endif  
			
test_ats_solver_request_and_add_address_ril_SOURCES = \
 test_ats_solver_request_and_add_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_request_and_add_address_ril_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la


test_ats_solver_request_and_delete_address_proportional_SOURCES = \
 test_ats_solver_request_and_delete_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_request_and_delete_address_proportional_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
	
if HAVE_LIBGLPK	
test_ats_solver_request_and_delete_address_mlp_SOURCES = \
 test_ats_solver_request_and_delete_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_request_and_delete_address_mlp_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la
endif  
			
test_ats_solver_request_and_delete_address_ril_SOURCES = \
 test_ats_solver_request_and_delete_address.c \
 test_ats_api_common.c test_ats_api_common.h
test_ats_solver_request_and_delete_address_ril_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la



#test_ats_api_scheduling_min_bw_SOURCES = \
# test_ats_api_scheduling_min_bw.c test_ats_api_common.c
#test_ats_api_scheduling_min_bw_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/testing/libgnunettesting.la \
#  $(top_builddir)/src/ats/libgnunetats.la  
#
#test_ats_api_scheduling_check_min_bw_alt_SOURCES = \
# test_ats_api_scheduling_check_min_bw_alt.c test_ats_api_common.c
#test_ats_api_scheduling_check_min_bw_alt_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/testing/libgnunettesting.la \
#  $(top_builddir)/src/ats/libgnunetats.la  


#test_ats_api_scheduling_update_address_SOURCES = \
# test_ats_api_scheduling_update_address.c test_ats_api_common.c
#test_ats_api_scheduling_update_address_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/testing/libgnunettesting.la \
#  $(top_builddir)/src/ats/libgnunetats.la  
  
#test_ats_api_scheduling_destroy_inbound_connection_SOURCES = \
# test_ats_api_scheduling_destroy_inbound_connection.c test_ats_api_common.c
#test_ats_api_scheduling_destroy_inbound_connection_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/testing/libgnunettesting.la \
#  $(top_builddir)/src/ats/libgnunetats.la

#test_ats_api_scheduling_block_and_reset_SOURCES = \
# test_ats_api_scheduling_block_and_reset.c test_ats_api_common.c
#test_ats_api_scheduling_block_and_reset_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/testing/libgnunettesting.la \
#  $(top_builddir)/src/ats/libgnunetats.la

#test_ats_api_performance_feedback_SOURCES = \
# test_ats_api_performance_feedback.c
#test_ats_api_performance_feedback_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/testing/libgnunettesting.la \
#  $(top_builddir)/src/hello/libgnunethello.la \
#  $(top_builddir)/src/ats/libgnunetats.la    



#test_ats_api_performance_address_info_SOURCES = \
# test_ats_api_performance_address_info.c
#test_ats_api_performance_address_info_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/testing/libgnunettesting.la \
#  $(top_builddir)/src/hello/libgnunethello.la \
#  $(top_builddir)/src/ats/libgnunetats.la


#test_ats_simplistic_SOURCES = \
# test_ats_simplistic.c test_ats_api_common.c
#test_ats_simplistic_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/testing/libgnunettesting.la \
#  $(top_builddir)/src/hello/libgnunethello.la \
#  $(top_builddir)/src/ats/libgnunetats.la    

#test_ats_simplistic_switch_networks_SOURCES = \
# test_ats_simplistic_switch_networks.c test_ats_api_common.c
#test_ats_simplistic_switch_networks_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/testing/libgnunettesting.la \
#  $(top_builddir)/src/ats/libgnunetats.la

#test_ats_simplistic_change_preference_SOURCES = \
# test_ats_simplistic_change_preference.c test_ats_api_common.c
#test_ats_simplistic_change_preference_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/testing/libgnunettesting.la \
#  $(top_builddir)/src/ats/libgnunetats.la

#test_ats_change_preference_SOURCES = \
# test_ats_change_preference.c test_ats_api_common.c
#test_ats_change_preference_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/testing/libgnunettesting.la \
#  $(top_builddir)/src/ats/libgnunetats.la


#test_ats_mlp_SOURCES = \
#  $(GN_MLP_SRC) test_ats_mlp.c test_ats_api_common.c gnunet-service-ats_normalization.c
#test_ats_mlp_LDADD = \
#  $(GN_LIBGLPK) \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/statistics/libgnunetstatistics.la \
#  $(top_builddir)/src/ats/libgnunetats.la  

#test_ats_mlp_update_SOURCES = \
#  $(GN_MLP_SRC) test_ats_mlp_update.c test_ats_api_common.c gnunet-service-ats_normalization.c
#test_ats_mlp_update_LDADD = \
#  $(GN_LIBGLPK) \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/statistics/libgnunetstatistics.la \
#  $(top_builddir)/src/ats/libgnunetats.la  

#perf_ats_mlp_SOURCES = \
#  $(GN_MLP_SRC) perf_ats_mlp.c test_ats_api_common.c gnunet-service-ats_normalization.c
#perf_ats_mlp_LDADD = \
#  $(GN_LIBGLPK) \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/statistics/libgnunetstatistics.la \
#  $(top_builddir)/src/ats/libgnunetats.la  

#test_ats_normalization_update_quality_SOURCES = \
#  test_ats_normalization_update_quality.c test_ats_api_common.c
#test_ats_normalization_update_quality_LDADD = \
#  $(GN_LIBGLPK) \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/statistics/libgnunetstatistics.la \
#  $(top_builddir)/src/testing/libgnunettesting.la \
#  $(top_builddir)/src/ats/libgnunetats.la  
#endif
EXTRA_DIST = \
  ats.h \
  test_ats_api.conf \
  test_ats_mlp.conf \
  test_ats_solver_default.conf \
  test_ats_solver_proportional.conf \
  test_ats_solver_mlp.conf \
  test_ats_solver_ril.conf 
