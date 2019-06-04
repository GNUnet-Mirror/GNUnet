# - Try to find idn2
# Once done this will define
#
#  IDN2_FOUND - system has idn2
#  IDN2_INCLUDE_DIRS - the idn2 include directory
#  IDN2_LIBRARIES - Link these to use idn2
#  IDN2_DEFINITIONS - Compiler switches required for using idn2
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

if (IDN2_LIBRARIES AND IDN2_INCLUDE_DIRS)
    # in cache already
    # set(IDN2_FOUND TRUE)
else (IDN2_LIBRARIES AND IDN2_INCLUDE_DIRS)

    set(_IDN2_ROOT_PATHS
        "$ENV{PROGRAMFILES}/libidn2"
    )

    find_path(IDN2_ROOT_DIR
        NAMES
            include/idn2.h
        PATHS
            ${_IDN2_ROOT_PATHS}
    )
    mark_as_advanced(IDN2_ROOT_DIR)

    find_path(IDN2_INCLUDE_DIR
        NAMES
            idn2.h
	    idn2/idn2.h
        PATHS
            /usr/local/include
            /opt/local/include
            /sw/include
            /usr/lib/sfw/include
            ${IDN2_ROOT_DIR}/include
    )
    set(IDN2_INCLUDE_DIRS ${IDN2_INCLUDE_DIR})

    find_library(IDN2_LIBRARY
        NAMES
            libidn2
        PATHS
            /opt/local/lib
            /sw/lib
            /usr/sfw/lib/64
            /usr/sfw/lib
	    ${IDN2_ROOT_DIR}/lib
    )
    set(IDN2_LIBRARIES ${IDN2_LIBRARY})

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(IDN2 DEFAULT_MSG IDN2_LIBRARIES IDN2_INCLUDE_DIRS)

    # show the IDN2_INCLUDE_DIRS and IDN2_LIBRARIES variables only in the advanced view
    mark_as_advanced(IDN2_INCLUDE_DIRS IDN2_LIBRARIES)

endif (IDN2_LIBRARIES AND IDN2_INCLUDE_DIRS)

