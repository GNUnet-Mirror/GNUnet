pcfiles = \
       gnunetats.pc \
       gnunetarm.pc \
       gnunetblock.pc \
       gnunetcore.pc \
       gnunetdatacache.pc \
       gnunetdatastore.pc \
       gnunetdht.pc \
       gnunetdns.pc \
       gnunetdnsparser.pc \
       gnunetdv.pc \
       gnunetfragmentation.pc \
       gnunetfs.pc \
       gnunetgns.pc \
       gnunethello.pc \
       gnunetmesh.pc \
       gnunetmysql.pc \
       gnunetnamestore.pc \
       gnunetnat.pc \
       gnunetnse.pc \
       gnunetpeerinfo.pc \
       gnunetpostgres.pc \
       gnunetregex.pc \
       gnunetstatistics.pc \
       gnunettestbed.pc \
       gnunettesting.pc \
       gnunettransport.pc \
       gnunettun.pc \
       gnunetutil.pc \
       gnunetvpn.pc 

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
       gnunetats.pc.in \
       gnunetblock.pc.in \
       gnunetcore.pc.in \
       gnunetdatacache.pc.in \
       gnunetdatastore.pc.in \
       gnunetdht.pc.in \
       gnunetdns.pc.in \
       gnunetdnsparser.pc.in \
       gnunetdv.pc.in \
       gnunetfragmentation.pc.in \
       gnunetfs.pc.in \
       gnunetgns.pc.in \
       gnunethello.pc.in \
       gnunetlockmanager.pc.in \
       gnunetmesh.pc.in \
       gnunetmysql.pc.in \
       gnunetnamestore.pc.in \
       gnunetnat.pc.in \
       gnunetnse.pc.in \
       gnunetpeerinfo.pc.in \
       gnunetpostgres.pc.in \
       gnunetregex.pc.in \
       gnunetstatistics.pc.in \
       gnunetstream.pc.in \
       gnunettestbed.pc.in \
       gnunettesting.pc.in \
       gnunettransport.pc.in \
       gnunettun.pc.in \
       gnunetutil.pc.in \
       gnunetvpn.pc.in 

CLEANFILES = $(pcfiles)
AM_CPPFLAGS = -I$(top_srcdir)/src/include


