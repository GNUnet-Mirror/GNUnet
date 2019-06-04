# Try to find /usr/include/microhttpd.h
# Once done, this will define
#
# MICROHTTPD_FOUND - system has microhttpd developement header
# MICROHTTPD_INCLUDE_DIRS - the microhttpd include directories
# MICROHTTPD_LIBRARIES - the microhttpd library name(s)

if(MICROHTTPD_INCLUDE_DIRS AND MICROHTTPD_LIBRARIES)
set(MICROHTTPD_FIND_QUIETLY TRUE)
endif(MICROHTTPD_INCLUDE_DIRS AND MICROHTTPD_LIBRARIES)

find_path(MICROHTTPD_INCLUDE_DIR microhttpd.h)

find_library(MICROHTTPD_LIBRARY microhttpd
                          HINTS
                          /usr/lib64
			  /usr/lib
			  /usr/pkg/lib
                          )

set(MICROHTTPD_INCLUDE_DIRS ${MICROHTTPD_INCLUDE_DIR})
set(MICROHTTPD_LIBRARIES ${MICROHTTPD_LIBRARY})

# handle the QUIETLY and REQUIRED arguments and set MICROHTTPD_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(microhttpd DEFAULT_MSG MICROHTTPD_INCLUDE_DIR )

mark_as_advanced(MICROHTTPD_INCLUDE_DIR)

# include_directories("src/include")
check_c_source_compiles("
#include \"${CMAKE_CURRENT_SOURCE_DIR}/src/include/platform.h\"
#include <microhttpd.h>
#if (MHD_VERSION < 0x0094200)
#error needs at least version 0.9.42
#endif
int main () { return 0; }"
HAVE_LIBMICROHTTPD)
