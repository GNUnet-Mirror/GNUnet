pcfiles = \
       gnunetarm.pc \
       gnunetblock.pc \
       gnunetcore.pc \
       gnunetdatacache.pc \
       gnunetdatastore.pc \
       gnunetdht.pc \
       gnunetdhtlog.pc \
       gnunetdv.pc \
       gnunetfragmentation.pc \
       gnunetfs.pc \
       gnunethello.pc \
       gnunetnse.pc \
       gnunetnat.pc \
       gnunetpeerinfo.pc \
       gnunetstatistics.pc \
       gnunettesting.pc \
       gnunettransport.pc \
       gnunetutil.pc

all-local: $(pcfiles)

cp_verbose = $(cp_verbose_$(V))
cp_verbose_ = $(cp_verbose_$(AM_DEFAULT_VERBOSITY))
cp_verbose_0 = @echo "  CP     $@";

%.pc: %.pc
	$(cp_verbose_0)cp $< $@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(pcfiles)

EXTRA_DIST = \
       gnunetarm.pc.in \
       gnunetblock.pc.in \
       gnunetcore.pc.in \
       gnunetdatacache.pc.in \
       gnunetdatastore.pc.in \
       gnunetdht.pc.in \
       gnunetdhtlog.pc.in \
       gnunetdv.pc.in \
       gnunetfragmentation.pc.in \
       gnunetfs.pc.in \
       gnunethello.pc.in \
       gnunetnat.pc.in \
       gnunetnse.pc.in \
       gnunetpeerinfo.pc.in \
       gnunetstatistics.pc.in \
       gnunettesting.pc.in \
       gnunettransport.pc.in \
       gnunetutil.pc.in

CLEANFILES = $(pcfiles)
INCLUDES = -I$(top_srcdir)/src/include


