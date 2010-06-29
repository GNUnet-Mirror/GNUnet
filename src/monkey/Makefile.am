INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


lib_LTLIBRARIES = libgnunetmonkey.la

libgnunetmonkey_la_SOURCES = \
  monkey_api.c monkey.h
libgnunetmonkey_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lesmtp
libgnunetmonkey_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
 gnunet-monkey \
 gnunet-service-monkey \
 bug_null_pointer_exception \
 mail_sender

gnunet_monkey_SOURCES = \
 mi_gdb.h \
 alloc.c \
 breakpoint.c \
 connect.c \
 cpp_int.cc \
 data_man.c \
 error.c \
 get_free_pty.c \
 get_free_vt.c \
 gnunet-monkey.c \
 misc.c \
 parse.c \
 prg_control.c \
 stack_man.c \
 symbol_query.c \
 target_man.c \
 thread.c \
 var_obj.c
            
gnunet_monkey_LDADD = \
  $(top_builddir)/src/monkey/libgnunetmonkey.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)



gnunet_service_monkey_SOURCES = \
 gnunet-service-monkey.c         
gnunet_service_monkey_LDADD = \
  $(top_builddir)/src/monkey/libgnunetmonkey.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


mail_sender_SOURCES = \
	mail_sender.c
mail_sender_LDADD = \
	$(top_builddir)/src/monkey/libgnunetmonkey.la \
  	$(top_builddir)/src/util/libgnunetutil.la \
  	$(GN_LIBINTL)

bug_null_pointer_exception_SOURCES = \
	bug_null_pointer_exception.c
bug_null_pointer_exception_LDADD = \
	$(top_builddir)/src/monkey/libgnunetmonkey.la \
  	$(top_builddir)/src/util/libgnunetutil.la \
  	$(GN_LIBINTL)


  	
check_PROGRAMS = \
 test_monkey_api

TESTS = $(check_PROGRAMS) $(check_SCRIPTS)

test_monkey_api_SOURCES = \
 test_monkey_api.c
test_monkey_api_LDADD = \
  $(top_builddir)/src/monkey/libgnunetmonkey.la \
  $(top_builddir)/src/util/libgnunetutil.la  

check_SCRIPTS = \
  test_gnunet_monkey.sh

EXTRA_DIST = \
  test_monkey_api_data.conf \
  $(check_SCRIPTS) 


