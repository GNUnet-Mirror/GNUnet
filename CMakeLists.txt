# this file is in the public-domain.
# alternatively, the 0BSD license applies
# Authored by the GNUnet e.V. in 2019,
# contributed by ng0 <ng0@gnunet.org>.
# ----

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
	message(FATAL_ERROR "Prevented in-tree build. This is bad practice.")
endif(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})

# ---- project setup
# Make sure this version matches ${GR_CMAKE_MIN_VERSION} (a variable can't be
# used here).
cmake_minimum_required(VERSION 3.8)
project(GNUnet CXX C)
# version
set (gnunet_VERSION_MAJOR 0)
set (gnunet_VERSION_MINOR 11)
set (gnunet_VERSION_PATCH 5)
set (gnunet_VERSION "${gnunet_VERSION_MAJOR}.${gnunet_VERSION_MINOR}.${gnunet_VERSION_PATCH}")
# git version
# TODO
# git_version=$(cd $srcdir ; git rev-list --full-history --all --abbrev-commit | head -n 1 2>/dev/null)

# ---- cmake
# Make sure our local CMake Modules path comes first
# list(INSERT CMAKE_MODULE_PATH 0 ${CMAKE_SOURCE_DIR}/cmake/Modules)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)

# ---- packages
# pkgconf
set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/share/pkgconfig"
	CACHE
	PATH
	"Installation directory for pkgconfig (.pc) files"
	)
if(NOT SKIP_INSTALL_FILES AND NOT SKIP_INSTALL_ALL)
	install(FILES foo.pc DESTINATION "${INSTALL_PKGCONFIG_DIR}")
endif()

enable_testing()
include(${CMAKE_MODULE_PATH}/../DefineOptions.cmake)

set (CMAKE_C_CFLAGS "${CMAKE_C_FLAGS} -O0 -Wall")
set (CMAKE_POSITION_INDEPENDENT_CODE true)


if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
	add_definitions(-Wno-pointer-sign)
endif()

if (ENABLE_LINKER_HARDENING)
	link_libraries("-z relro -z now")
endif()

if (ENABLE_SANITIZER)
	link_libraries("-fsanitize=address,undefined -fno-omit-frame-pointer")
endif()


add_custom_target(uninstall
	COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake/Modules/cmake_uninstall.cmake)

if(APPLE)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-common")
	if(ENABLE_LINKER_HARDENING)
		message(FATAL_ERROR "The linker hardening used is not compatible with Apple")
	endif()
endif()
if(LINUX)
endif()
if(FREEBSD)
	set(BSD TRUE)
endif()
if(OPENBSD)
	set(BSD TRUE)
endif()
if(NETBSD)
	LIST(APPEND CMAKE_LIBRARY_PATH "/usr/pkg/lib")
	LIST(APPEND CMAKE_PROGRAM_PATH "/usr/pkg/bin")
	set(BSD TRUE)
endif()
if(SOLARIS)
endif()
if(ARM-LINUX)
endif()
if(CYGWIN)
endif()
if(MINGW)
endif()
if(GNU)
endif()
if(WIN32)
endif()

include(CheckLibraryExists)

# libm
check_library_exists(m log PATH LIBM)
if (LIBM)
	list(APPEND DEPLIBS "m")
endif()

# socket
check_library_exists(socket socket PATH HAVE_SOCKET)

# libc
check_library_exists(c getloadavg PATH HAVE_GETLOADAVG)

# sqlite3
find_package (SQLite3)
if (SQLITE3_FOUND)
	include_directories(${SQLITE3_INCLUDE_DIRS})
	target_link_libraries (gnunet ${SQLITE3_LIBRARIES})
#else (NOT SQLITE3_FOUND)
#	message(FATAL_ERROR "sqlite3 is required")
endif (SQLITE3_FOUND)

# posix
include(CheckIncludeFile)
include(CheckIncludeFileCXX)
include(CheckFunctionExists)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckTypeSize)
INCLUDE(CheckCSourceRuns)
INCLUDE(CheckCSourceCompiles)
INCLUDE(CheckStructHasMember)
INCLUDE(TestBigEndian)
INCLUDE(GNUInstallDirs)

include(${CMAKE_MODULE_PATH}/PosixHeaders.cmake)
check_function_exists(kvm_open HAVE_KVM_OPEN)
check_function_exists(kstat_open HAVE_KSTAT_OPEN)
# FreeBSD
include(${CMAKE_MODULE_PATH}/FreeBSDHeaders.cmake)

# getopt
find_package(Getopt)

# curl
if(ENABLE_CURL AND NOT ENABLE_GNURL)
	find_package(CURL 7.34.0)
endif()

# gnurl
if(ENABLE_GNURL AND NOT ENABLE_CURL)
	find_package(GNURL 7.34.0)
endif()
if (ENABLE_CURL AND ENABLE_GNURL)
	message(FATAL_ERROR "Can only build with gnurl or curl")
endif()

# glibc NSS
check_library_exists(nss NSS_STATUS_UNAVAIL PATH HAVE_NSS)

# libatomic
check_library_exists(atomic __atomic_load_8 PATH HAVE_ATOMIC)

# sudo
find_package(SUDO)

# doas
find_package(DOAS)

# glpk
find_package (GLPK 4.43)
check_library_exists(glpk glp_init_env PATH GLPK_INIT_EXISTS)
check_library_exists(glpk glp_iocp.presolve PATH GLPK_IOCP_EXISTS)

# gcrypt
find_package (GCrypt 1.6.0 REQUIRED)
if (NOT GCrypt_FOUND)
	message(FATAL_ERROR "Could not find GCrypt")
endif (NOT GCrypt_FOUND)

# gnutls
find_package (GnuTLS)

# mysql
find_package (MySQL)

# postgres
find_package (PostgreSQL)

# gstreamer

# jansson
find_package (Jansson)
if (Jansson_FOUND)
	set(HAVE_JSON ON)
endif()

# libpulse
find_package (Pulse)
#check_library_exists(pulse pa_stream_peek PATH PULSE_EXISTS)

# libbluez
find_package(BlueZ)

# microhttpd
find_package(MicroHTTPD 0.9.63)

# libopus
check_library_exists(opus opus_decode_float PATH OPUS_EXISTS)

# pbc
check_include_file("pbc/pbc.h" HAVE_PBC_H)

# abe
find_path(GABE_INCLUDE_PATH
	NAMES
	gabe.h)
check_include_file("gabe.h" HAVE_GABE_H)

# texinfo
find_program(MAKEINFO_EXECUTABLE makeinfo MAKEINFO_EXISTS)
if(MAKEINFO_EXISTS)
	set(WITH_DOCUMENTATION ON)
endif()
# belongs in doc/
if (WITH_DOCUMENTATION)
	find_program(MAKEINFO_EXECUTABLE makeinfo)
	set(info_in ${CMAKE_CURRENT_SOURCE_DIR}/bla.texi)
	set(info_out ${CMAKE_CURRENT_BINARY_DIR}/bla.info)
	add_custom_command(OUTPUT ${info_out}
			   COMMAND ${MAKEINFO_EXECUTABLE} -o ${info_out} ${info_in}
			   DEPENDS ${info_in}
			   COMMENT "Creating Info file ${info_out}"
			   VERBATIM)
	add_custom_target(info ALL DEPENDS ${info_out})
endif()

# texi2mdoc
find_package(Texi2mdoc)
if (HAVE_Texi2mdoc)
	message("FOUND TEXI2MDOC")
endif()

# libextractor
# find_package(Extractor)
check_library_exists(extractor EXTRACTOR_plugin_add_defaults PATH EXTRACTOR_EXISTS)

# zbar
# find_package(Zbar)
check_library_exists(zbar zbar_processor_create PATH ZBAR_EXISTS)

# glib
find_package(GLIB)

# idn
find_package(IDN)

# idn2
find_package(IDN2)

# zlib
find_package(ZLIB)

# perl
find_package(Perl 5.0.0)

# python
find_package(Python)

# upnpc
find_package(Upnpc)

# ip
find_package(Ip)

# iptables
find_package(Iptables)
find_package(Ip6tables)

# ifconfig
find_package(Ifconfig)

# ssh
find_package(SSH)

# sysctl
find_package(Sysctl)

# plibc
if (MINGW)
	check_library_exists(plibc plibc_init PATH PLIBC_FOUND)
	if (NOT PLIBC_FOUND)
		message(FATAL_ERROR "PLibC is required on Windows")
	endif()
	check_library_exists(regexec PATH REGEXEC_FOUND)
	if (NOT REGEXEC_FOUND)
		message(FATAL_ERROR "libgnurx is required on Windows")
	endif()
endif()

# Do we really need 0.18.1?
# Gettext
find_package(Gettext 0.18.1)

# standard typedefs, structures and compiler characteristics.
check_c_source_compiles("
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>"
HAVE_SOCKADDR_IN_SIN_LEN)

# TODO: Move to FindHMAC.cmake?
check_c_source_compiles("
#include <gcrypt.h>
#include <stdio.h>
gcry_md_hd_t mac;

unsigned char data[] = { 0xbf, 0x16, 0x6e, 0x46, 0x3a, 0x6c, 0xf3, 0x93, 0xa7, 0x72,
0x11, 0xa1, 0xdc, 0x0b, 0x07, 0xdb, 0x1a, 0x5e, 0xd9, 0xb9, 0x81, 0xbe,
0xea, 0xe4, 0x31, 0x5f, 0x24, 0xff, 0xfe, 0x50, 0x8a, 0xde };
unsigned char key[] = { 0xfc, 0x62, 0x76, 0x35 };
unsigned char result[] = {0xa2, 0xb, 0x1, 0xd9, 0xc0, 0x8b, 0x5a, 0x12, 0x80,
0xd5, 0x50, 0x12, 0x8e, 0xd0, 0x5b, 0xb6, 0x5c, 0x87, 0x24, 0xe2, 0xd0,
0xd2, 0xaf, 0x63, 0xae, 0xd1, 0xd6, 0x64, 0x14, 0xe3, 0x6e, 0x61, 0x5b,
0xd, 0xba, 0x17, 0x7d, 0xd3, 0x10, 0xb1, 0x37, 0x41, 0x91, 0x7d, 0xeb,
0x1, 0x4d, 0x71, 0xe8, 0x59, 0x71, 0x42, 0x8e, 0xd6, 0xf3, 0x29, 0x3b,
0x90, 0xf2, 0xd1, 0xaf, 0x65, 0x1e, 0xb3};

if (!gcry_check_version (GCRYPT_VERSION))
{
fprintf (stderr, \"Version mismatch %s <-> %s \n\", gcry_check_version (NULL), GCRYPT_VERSION);
return 1;
}

gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

if (gcry_md_open(&mac, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC) != GPG_ERR_NO_ERROR)
{
fprintf (stderr, \"gcry_md_open error\n\");
return 2;
}

gcry_md_setkey (mac, key, sizeof (key));
gcry_md_write (mac, data, sizeof (data));

if (memcmp(gcry_md_read (mac, 0), result, gcry_md_get_algo_dlen (gcry_md_get_algo (mac))) != 0)
{
fprintf (stderr, \"memcmp error\n\");
return 3;
}

gcry_md_close (mac);

return 0;
" HAVE_HMAC)

# TODO: Move to the modules?
MESSAGE(STATUS "*********************************************************")
MESSAGE(STATUS ${PROJECT_NAME} " " ${gnunet_VERSION} " configuration:")
MESSAGE(STATUS "Build type: " ${CMAKE_BUILD_TYPE})
MESSAGE(STATUS "Library Type: " ${LIB_TYPE})
MESSAGE(STATUS "Compiler flags: " ${CMAKE_CXX_COMPILE_FLAGS})
MESSAGE(STATUS "Compiler cxx debug flags: " ${CMAKE_CXX_FLAGS_DEBUG})
MESSAGE(STATUS "Compiler cxx release flags: " ${CMAKE_CXX_FLAGS_RELEASE})
MESSAGE(STATUS "Compiler cxx min size flags: " ${CMAKE_CXX_FLAGS_MINSIZEREL})
MESSAGE(STATUS "Compiler cxx flags: " ${CMAKE_CXX_FLAGS})
MESSAGE(STATUS "Linker flags: " ${CMAKE_LD_FLAGS})
MESSAGE(STATUS "Destination directory: " ${DESTDIR})
MESSAGE(STATUS "Features: " ${GNUNET_FEATURES})
MESSAGE(STATUS "*********************************************************")
include(${CMAKE_MODULE_PATH}/../PostConfigureMsg.cmake)
