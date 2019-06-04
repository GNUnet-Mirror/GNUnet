#=============================================================================
# Copyright 2019 GNUnet e.V.
#
# Distributed under the OSI-approved BSD License (the "License");
# see accompanying file Copyright.txt for details.
#
# This software is distributed WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the License for more information.
#=============================================================================
# (To distribute this file outside of CMake, substitute the full
#  License text for the above reference.)

include(FindCygwin)

find_program(IP6TABLES
	ip6tables
	PATH
	${CYGWIN_INSTALL_PATH}/bin
	)
mark_as_advanced(IP6TABLES)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Ip6tables
	REQUIRED_VARS IP6TABLES
	)
