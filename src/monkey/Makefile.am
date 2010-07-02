INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


if !MINGW

bin_PROGRAMS = \
 gnunet-monkey \
 gnunet-service-monkey \
 mail_sender

noinst_PROGRAMS = \
 bug_null_pointer_exception 

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
 gnunet-monkey.c

gnunet_monkey_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


gnunet_service_monkey_SOURCES = \
 gnunet-service-monkey.c         
gnunet_service_monkey_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


mail_sender_SOURCES = \
	mail_sender.c
mail_sender_LDADD = \
	$(top_builddir)/src/util/libgnunetutil.la \
        -lesmtp \
	$(GN_LIBINTL)

bug_null_pointer_exception_SOURCES = \
	bug_null_pointer_exception.c
bug_null_pointer_exception_LDADD = \
	$(top_builddir)/src/util/libgnunetutil.la \
	$(GN_LIBINTL)


#TESTS = $(check_PROGRAMS) $(check_SCRIPTS)

check_SCRIPTS = \
  test_gnunet_monkey.sh

EXTRA_DIST = \
  test_gnunet_monkey_data.conf \
  $(check_SCRIPTS) 

endif

