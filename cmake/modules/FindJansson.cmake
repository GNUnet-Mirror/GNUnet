# - Try to find jansson
# Once done this will define
#
#  JANSSON_FOUND - system has jansson
#  JANSSON_INCLUDE_DIRS - the jansson include directory
#  JANSSON_LIBRARIES - Link these to use jansson
#  JANSSON_DEFINITIONS - Compiler switches required for using jansson
#
#=============================================================================
#  Copyright (c) 2019 GNUnet eV
#
#  Distributed under the OSI-approved BSD License (the "License");
#  see accompanying file Copyright.txt for details.
#
#  This software is distributed WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the License for more information.
#=============================================================================
#

if (JANSSON_LIBRARIES AND JANSSON_INCLUDE_DIRS)
    # in cache already
    # set(JANSSON_FOUND TRUE)
else (JANSSON_LIBRARIES AND JANSSON_INCLUDE_DIRS)

    set(_JANSSON_ROOT_PATHS
        "$ENV{PROGRAMFILES}/libjansson"
    )

    find_path(JANSSON_ROOT_DIR
        NAMES
            include/jansson.h
        PATHS
            ${_JANSSON_ROOT_PATHS}
    )
    #mark_as_advanced(ZLIB_ROOT_DIR)
    mark_as_advanced(JANSSON_ROOT_DIR)

    find_path(JANSSON_INCLUDE_DIR
        NAMES
            jansson.h
        PATHS
            /usr/local/include
            /opt/local/include
            /sw/include
            /usr/lib/sfw/include
            ${JANSSON_ROOT_DIR}/include
    )
    set(JANSSON_INCLUDE_DIRS ${JANSSON_INCLUDE_DIR})

    find_library(JANSSON_LIBRARY
        NAMES
            jansson
        PATHS
            /opt/local/lib
            /sw/lib
            /usr/sfw/lib/64
            /usr/sfw/lib
	    ${JANSSON_ROOT_DIR}/lib
    )
    set(JANSSON_LIBRARIES ${JANSSON_LIBRARY})

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(Jansson DEFAULT_MSG JANSSON_LIBRARIES JANSSON_INCLUDE_DIRS)

    # show the JANSSON_INCLUDE_DIRS and JANSSON_LIBRARIES variables only in the advanced view
    mark_as_advanced(JANSSON_INCLUDE_DIRS JANSSON_LIBRARIES)

endif (JANSSON_LIBRARIES AND JANSSON_INCLUDE_DIRS)

