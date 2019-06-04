# Try to find GLPK
# Once done, this will define
#
# GLPK_FOUND - system has glpk developement header
# GLPK_INCLUDE_DIRS - the glpk include directories
# GLPK_LIBRARIES - the glpk library name(s)
#
# BSD-2 clause licensed GNUnet eV 2019

if(GLPK_INCLUDE_DIRS AND GLPK_LIBRARIES)
set(GLPK_FIND_QUIETLY TRUE)
endif(GLPK_INCLUDE_DIRS AND GLPK_LIBRARIES)

find_path(GLPK_INCLUDE_DIR glpk.h)

find_library(GLPK_LIBRARY libglpk
                          HINTS
                          /usr/lib64
			  /usr/lib
			  /usr/pkg/lib
                          )

set(GLPK_INCLUDE_DIRS ${GLPK_INCLUDE_DIR})
set(GLPK_LIBRARIES ${GLPK_LIBRARY})

# handle the QUIETLY and REQUIRED arguments and set GLPK_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(glpk DEFAULT_MSG GLPK_INCLUDE_DIR )

mark_as_advanced(GLPK_INCLUDE_DIR)
