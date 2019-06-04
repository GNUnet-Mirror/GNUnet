# - Try to find pulseaudio
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

find_path(PULSEAUDIO_INCLUDE_DIR
	pulse/pulseaudio.h
	HINTS "/usr/pkg/include" "/usr/include" "/include")

find_library(PULSEAUDIO_LIBRARY
	NAMES pulse libpulse
	HINTS "/usr/pkg/lib" "/usr/lib" "/lib")

find_library(PULSEAUDIO_MAINLOOP_LIBRARY
	NAMES pulse-mainloop-glib libpulse-mainloop-glib
	HINTS "/usr/pkg/lib" "/usr/lib" "/lib")
