INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


if !MINGW
if HAVE_ESMTP
if HAVE_OPENSSL


lib_LTLIBRARIES = libmonkeyedb.la \
				  libmonkeyaction.la

libmonkeyedb_la_SOURCES = \
  edb_api.c \
  gnunet_monkey_edb.h

libmonkeyedb_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lsqlite3 \
  $(GN_LIBINTL) $(XLIB)  

libmonkeyaction_la_SOURCES = \
  action_api.c \
  gnunet_monkey_action.h

libmonkeyaction_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)  

bin_PROGRAMS = \
 gnunet-monkey \
 gnunet-service-monkey 

noinst_PROGRAMS = \
 bug_null_pointer_exception \
 bug_bad_memory_access \
 bug_assertion_failure

gnunet_monkey_SOURCES = \
 gdbmi.h \
 gdbmi_alloc.c \
 gdbmi_breakpoint.c \
 gdbmi_connect.c \
 gdbmi_data_man.c \
 gdbmi_error.c \
 gdbmi_get_free_pty.c \
 gdbmi_get_free_vt.c \
 gdbmi_misc.c \
 gdbmi_parse.c \
 gdbmi_prg_control.c \
 gdbmi_stack_man.c \
 gdbmi_symbol_query.c \
 gdbmi_target_man.c \
 gdbmi_thread.c \
 gdbmi_var_obj.c \
 gnunet-monkey.c \
 mail_sender.c

gnunet_monkey_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/monkey/libmonkeyedb.la \
  $(top_builddir)/src/monkey/libmonkeyaction.la \
  -lesmtp \
  $(GN_LIBINTL)


gnunet_service_monkey_SOURCES = \
 gnunet-service-monkey.c         
gnunet_service_monkey_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


bug_null_pointer_exception:
	gcc -g -O0 -o bug_null_pointer_exception bug_null_pointer_exception.c

bug_bad_memory_access:
	gcc -g -O0 -o bug_bad_memory_access bug_bad_memory_access.c	

bug_assertion_failure:
	gcc -g -O0 -o bug_assertion_failure bug_assertion_failure.c	
	
check_PROGRAMS = \
    test_monkey_edb
    #test_gnunet_monkey	

if !DISABLE_TEST_RUN
# TESTS = $(check_SCRIPTS)
TESTS = $(check_PROGRAMS)
endif

test_monkey_edb_SOURCES = \
  test_monkey_edb.c
test_monkey_edb_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/monkey/libmonkeyedb.la

#test_gnunet_monkey_SOURCES = \
 #test_gnunet_monkey.c
#test_gnunet_monkey_LDADD = \
  #$(top_builddir)/src/arm/libgnunetarm.la \
  #$(top_builddir)/src/util/libgnunetutil.la  


check_SCRIPTS = \
  #test_gnunet_monkey.sh \
  #test_monkey_npe.sh

#EXTRA_DIST = \
#$(check_SCRIPTS) 
#test_gnunet_monkey_data.conf 

endif
endif
endif
