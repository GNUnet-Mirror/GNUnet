# - Try to find idn
# Once done this will define
#
#  IDN_FOUND - system has idn
#  IDN_INCLUDE_DIRS - the idn include directory
#  IDN_LIBRARIES - Link these to use idn
#  IDN_DEFINITIONS - Compiler switches required for using idn
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

if (IDN_LIBRARIES AND IDN_INCLUDE_DIRS)
    # in cache already
    # set(IDN_FOUND TRUE)
else (IDN_LIBRARIES AND IDN_INCLUDE_DIRS)

    set(_IDN_ROOT_PATHS
        "$ENV{PROGRAMFILES}/libidn"
    )

    find_path(IDN_ROOT_DIR
        NAMES
	include/idna.h
        PATHS
            ${_IDN_ROOT_PATHS}
    )
    mark_as_advanced(IDN_ROOT_DIR)

    find_path(IDN_INCLUDE_DIR
        NAMES
            idna.h
        PATHS
            /usr/local/include
            /opt/local/include
            /sw/include
            /usr/lib/sfw/include
            ${IDN_ROOT_DIR}/include
    )
    set(IDN_INCLUDE_DIRS ${IDN_INCLUDE_DIR})

    find_library(IDN_LIBRARY
        NAMES
            libidn
        PATHS
            /opt/local/lib
            /sw/lib
            /usr/sfw/lib/64
            /usr/sfw/lib
	    ${IDN_ROOT_DIR}/lib
    )
    set(IDN_LIBRARIES ${IDN_LIBRARY})

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(IDN DEFAULT_MSG IDN_LIBRARIES IDN_INCLUDE_DIRS)

    # show the IDN_INCLUDE_DIRS and IDN_LIBRARIES variables only in the advanced view
    mark_as_advanced(IDN_INCLUDE_DIRS IDN_LIBRARIES)

endif (IDN_LIBRARIES AND IDN_INCLUDE_DIRS)

