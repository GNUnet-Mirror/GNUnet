# ---- options
option(BUILD_MDOCPAGES "Install Texi2mdoc dump of Texinfo Handbooks" OFF)
option(BUILD_MANPAGES "Install man pages" ON)
option(BUILD_DOCUMENTATION "Install Handbooks typeset in Texinfo" ON)

option(ENABLE_EXPERIMENTAL "Enable experimental features" OFF)
option(ENABLE_MALICIOUS "Enable compilation of malicious code" OFF)
option(ENABLE_LINKER_HARDENING "Enable linker hardening (ELF-specific)" OFF)
option(ENABLE_SANITIZER "Enable Address Sanitizer and Undefined Behavior Sanitizer" OFF)

option(WITH_TESTING "Build with test units" OFF)

option(ENABLE_TALER_ONLY "Compiling for Taler wallet" OFF)
option(ENABLE_TALER_WALLET "Only compile for Taler wallet" OFF)
option(ENABLE_SUPERMUC "Build for the SuperMUC" OFF)

option(ENABLE_CURL "Build with curl" OFF)
option(ENABLE_GNURL "Build with gnurl" ON)

option(ENABLE_IDN "Build with idn" OFF)
option(ENABLE_IDN "Build with idn2" ON)

option(BUILD_SHARED_LIBS "Build shared libraries" ON)
