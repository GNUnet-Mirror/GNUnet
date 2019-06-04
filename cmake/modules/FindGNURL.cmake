# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
FindCURL
--------

Find the native CURL headers and libraries.

This module accept optional COMPONENTS to check supported features and
protocols::

  PROTOCOLS: ICT FILE FTP FTPS GOPHER HTTP HTTPS IMAP IMAPS LDAP LDAPS POP3
             POP3S RTMP RTSP SCP SFTP SMB SMBS SMTP SMTPS TELNET TFTP
  FEATURES:  SSL IPv6 UnixSockets libz AsynchDNS IDN GSS-API PSL SPNEGO
             Kerberos NTLM NTLM_WB TLS-SRP HTTP2 HTTPS-proxy

IMPORTED Targets
^^^^^^^^^^^^^^^^

This module defines :prop_tgt:`IMPORTED` target ``CURL::libcurl``, if
curl has been found.

Result Variables
^^^^^^^^^^^^^^^^

This module defines the following variables:

``CURL_FOUND``
  "True" if ``curl`` found.

``CURL_INCLUDE_DIRS``
  where to find ``curl``/``curl.h``, etc.

``CURL_LIBRARIES``
  List of libraries when using ``curl``.

``CURL_VERSION_STRING``
  The version of ``curl`` found.
#]=======================================================================]

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
	pkg_check_modules(PC_GNURL QUIET libgnurl)
  if(PC_GNURL_FOUND)
	  set(GNURL_VERSION_STRING ${PC_GNURL_VERSION})
	  pkg_get_variable(GNURL_SUPPORTED_PROTOCOLS libgnurl supported_protocols)
	  pkg_get_variable(GNURL_SUPPORTED_FEATURES libgnurl supported_features)
  endif()
endif()

# Look for the header file.
find_path(GNURL_INCLUDE_DIR
          NAMES gnurl/curl.h
	  HINTS ${PC_GNURL_INCLUDE_DIRS})
  mark_as_advanced(GNURL_INCLUDE_DIR)

  if(NOT GNURL_LIBRARY)
  # Look for the library (sorted from most current/relevant entry to least).
  find_library(GNURL_LIBRARY_RELEASE NAMES
      gnurl
    # Windows MSVC prebuilts:
      gnurllib
      libgnurl_imp
      curllib_static
    # Windows older "Win32 - MSVC" prebuilts (libcurl.lib, e.g. libcurl-7.15.5-win32-msvc.zip):
      libgnurl
      HINTS ${PC_GNURL_LIBRARY_DIRS}
  )
  mark_as_advanced(GNURL_LIBRARY_RELEASE)

  find_library(GNURL_LIBRARY_DEBUG NAMES
    # Windows MSVC CMake builds in debug configuration on vcpkg:
      libgnurl-d_imp
      libgnurl-d
      HINTS ${PC_GNURL_LIBRARY_DIRS}
  )
  mark_as_advanced(GNURL_LIBRARY_DEBUG)

  include(SelectLibraryConfigurations)
  select_library_configurations(GNURL)
endif()

if(GNURL_INCLUDE_DIR AND NOT GNURL_VERSION_STRING)
  foreach(_gnurl_version_header curlver.h curl.h)
	  if(EXISTS "${GNURL_INCLUDE_DIR}/gnurl/${_gnurl_version_header}")
		  file(STRINGS "${GNURL_INCLUDE_DIR}/gnurl/${_gnurl_version_header}" curl_version_str REGEX "^#define[\t ]+LIBCURL_VERSION[\t ]+\".*\"")

      string(REGEX REPLACE "^#define[\t ]+LIBCURL_VERSION[\t ]+\"([^\"]*)\".*" "\\1" CURL_VERSION_STRING "${curl_version_str}")
      unset(gnurl_version_str)
      break()
    endif()
  endforeach()
endif()

if(GNURL_FIND_COMPONENTS)
	set(GNURL_KNOWN_PROTOCOLS ICT FILE FTP FTPS GOPHER HTTP HTTPS IMAP IMAPS LDAP LDAPS POP3 POP3S RTMP RTSP SCP SFTP SMB SMBS SMTP SMTPS TELNET TFTP)
	set(GNURL_KNOWN_FEATURES  SSL IPv6 UnixSockets libz AsynchDNS IDN GSS-API PSL SPNEGO Kerberos NTLM NTLM_WB TLS-SRP HTTP2 HTTPS-proxy)
	foreach(component IN LISTS GNURL_KNOWN_PROTOCOLS GNURL_KNOWN_FEATURES)
		set(GNURL_${component}_FOUND FALSE)
  endforeach()
  if(NOT PC_GNURL_FOUND)
	  find_program(GNURL_CONFIG_EXECUTABLE NAMES gnurl-config)
	  if(GNURL_CONFIG_EXECUTABLE)
		  execute_process(COMMAND ${GNURL_CONFIG_EXECUTABLE} --version
			  OUTPUT_VARIABLE GNURL_CONFIG_VERSION_STRING
                      ERROR_QUIET
                      OUTPUT_STRIP_TRAILING_WHITESPACE)
	      execute_process(COMMAND ${GNURL_CONFIG_EXECUTABLE} --feature
		      OUTPUT_VARIABLE GNURL_CONFIG_FEATURES_STRING
                      ERROR_QUIET
                      OUTPUT_STRIP_TRAILING_WHITESPACE)
	      string(REPLACE "\n" ";" GNURL_SUPPORTED_FEATURES "${GNURL_CONFIG_FEATURES_STRING}")
	      execute_process(COMMAND ${GNURL_CONFIG_EXECUTABLE} --protocols
		      OUTPUT_VARIABLE GNURL_CONFIG_PROTOCOLS_STRING
                      ERROR_QUIET
                      OUTPUT_STRIP_TRAILING_WHITESPACE)
	      string(REPLACE "\n" ";" GNURL_SUPPORTED_PROTOCOLS "${GNURL_CONFIG_PROTOCOLS_STRING}")
    endif()

  endif()
  foreach(component IN LISTS GNURL_FIND_COMPONENTS)
	  list(FIND GNURL_KNOWN_PROTOCOLS ${component} _found)
    if(_found)
	    list(FIND GNURL_SUPPORTED_PROTOCOLS ${component} _found)
      if(_found)
	      set(GNURL_${component}_FOUND TRUE)
      elseif(GNURL_FIND_REQUIRED)
	      message(FATAL_ERROR "GNURL: Required protocol ${component} is not found")
      endif()
    else()
	    list(FIND GNURL_SUPPORTED_FEATURES ${component} _found)
      if(_found)
	      set(GNURL_${component}_FOUND TRUE)
      elseif(GNURL_FIND_REQUIRED)
	      message(FATAL_ERROR "GNURL: Required feature ${component} is not found")
      endif()
    endif()
  endforeach()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GNURL
	REQUIRED_VARS GNURL_LIBRARY GNURL_INCLUDE_DIR
	VERSION_VAR GNURL_VERSION_STRING
        HANDLE_COMPONENTS)

			  if(GNURL_FOUND)
				  set(GNURL_LIBRARIES ${GNURL_LIBRARY})
				  set(GNURL_INCLUDE_DIRS ${GNURL_INCLUDE_DIR})

				  if(NOT TARGET GNURL::libgnurl)
					  add_library(GNURL::libgnurl UNKNOWN IMPORTED)
					  set_target_properties(GNURL::libgnurl PROPERTIES
						  INTERFACE_INCLUDE_DIRECTORIES "${GNURL_INCLUDE_DIRS}")

					  if(EXISTS "${GNURL_LIBRARY}")
						  set_target_properties(GNURL::libgnurl PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES "C"
	IMPORTED_LOCATION "${GNURL_LIBRARY}")
    endif()
    if(GNURL_LIBRARY_RELEASE)
	    set_property(TARGET GNURL::libgnurl APPEND PROPERTY
        IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(GNURL::libgnurl PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES "C"
	IMPORTED_LOCATION_RELEASE "${GNURL_LIBRARY_RELEASE}")
    endif()
    if(GNURL_LIBRARY_DEBUG)
	    set_property(TARGET GNURL::libgnurl APPEND PROPERTY
        IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(GNURL::libgnurl PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES "C"
	IMPORTED_LOCATION_DEBUG "${GNURL_LIBRARY_DEBUG}")
    endif()
  endif()
endif()

