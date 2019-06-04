set(MAN1_PAGES
	gnunet-arm.1
	gnunet-ats.1
	gnunet-auto-share.1
	gnunet-bcd.1
	gnunet-cadet.1
	gnunet-config.1
	gnunet-conversation-test.1
	gnunet-conversation.1
	gnunet-core.1
	gnunet-datastore.1
	gnunet-directory.1
	gnunet-dns2gns.1
	gnunet-download.1
	gnunet-ecc.1
	gnunet-fs.1
	gnunet-gns-proxy-setup-ca.1
	gnunet-gns-proxy.1
	gnunet-gns.1
	gnunet-identity.1
	gnunet-namecache.1
	gnunet-namestore-fcfsd.1
	gnunet-namestore.1
	gnunet-nat-auto.1
	gnunet-nat-server.1
	gnunet-nat.1
	gnunet-nse.1
	gnunet-nse.1~
	gnunet-peerinfo.1
	gnunet-publish.1
	gnunet-qr.1
	gnunet-reclaim.1
	gnunet-resolver.1
	gnunet-revocation.1
	gnunet-scalarproduct.1
	gnunet-scrypt.1
	gnunet-search.1
	gnunet-statistics.1
	gnunet-testbed-profiler.1
	gnunet-testing-run-service.1
	gnunet-testing.1
	gnunet-timeout.1
	gnunet-transport-certificate-creation.1
	gnunet-transport.1
	gnunet-unindex.1
	gnunet-uri.1
	gnunet-vpn.1
	gnunet-zoneimport.1
	)
set(MAN5_PAGES
	gnunet.conf.5.in
	)
set(MAN7_PAGES
	gnunet.7
	gnunet-c-tutorial.7
	)

# TODO: Custom-commands and targets for HTML and plaintext output
# TODO: Custom-comand for texi2mdoc conversion
# TODO: Custom-command for .5.in -> .5 creation

FOREACH(MAN_PAGE ${MAN1_PAGES})
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${MAN_PAGE} DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
ENDFOREACH()
FOREACH(MAN_PAGE ${MAN5_PAGES})
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${MAN_PAGE} DESTINATION ${CMAKE_INSTALL_MANDIR}/man5)
ENDFOREACH()
FOREACH(MAN_PAGE ${MAN7_PAGES})
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${MAN_PAGE} DESTINATION ${CMAKE_INSTALL_MANDIR}/man7)
ENDFOREACH()
