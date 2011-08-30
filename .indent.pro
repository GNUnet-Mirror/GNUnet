//LRN extension for return values for prototypes
-nddd
//GNU (default) style: 	
//
//-nbad -bap -nbc -bbo -bl -bli2 -bls -ncdb -nce -cp1 -cs -di2
//-ndj -nfc1 -nfca -hnl -i2 -ip5 -lp -pcs -nprs -psl -saf -sai
//-saw -nsc -nsob
//
// -------
// int foo;
// char *bar;
// bar = strdup ("whe-e-e");
// -------
// int foo;
// char *bar;
//
// bar = strdup ("whe-e-e");
// -------
// Broken in indent-2.2.10
--blank-lines-after-declarations
//--no-blank-lines-after-declarations
//
// -------
// int foo (...) {
// ...
// }
// void bar (...) {
// ...
// }
// -------
// int foo (...) {
// ...
// }
//
// void bar (...) {
// ...
// }
// -------
--blank-lines-after-procedures
//
// -------
// /*
//    blah
//  */
// -------
// /*
//  * blah
//  */
// -------
// WARNING: tends to turn commented-out code chunks into star-walled comment blocks
--start-left-side-of-comments
//
// -------
// if (foo) { bar }
// -------
// if (foo)
//   {
//     bar
//   }
// -------
--braces-after-if-line
//
// -------
// if (foo)
//   {
//     bar
//   } else {
//     baz
//   }
// -------
// if (foo)
//   {
//     bar
//   }
//   else
//   {
//     baz
//   }
// -------
--dont-cuddle-else
//
// -------
// do
//   {
//     foo
//   }
//   while (bar)
// -------
// do
//   {
//     foo
//   } while (bar)
// -------
--dont-cuddle-do-while
//
// -------
// switch (foo)
//   {
//     case bar:
//       baz
//   }
// -------
// switch (foo)
//   {
//   case bar:
//     baz
//   }
// -------
--case-indentation0
//
// -------
// switch (foo)
//   {
//   case bar:
//     {
//       baz
//     }
//   }
// -------
// switch (foo)
//   {
//   case bar:
//   {
//     baz
//   }
//   }
// -------
// Yes, it looks wrong. However, braces inside cases should not be used like this anyway.
--case-brace-indentation0
//
// -------
// for (i = 0; foobar(i); i++);
// -------
// for (i = 0; foobar(i); i++) ;
// -------
--space-special-semicolon
//
// -------
// foo(bar)
// -------
// foo (bar)
// -------
--space-after-procedure-calls
//
// -------
// (int *)foo;
// (my_custom_type_that_was_not_passed_with_T_argument_see_below *)bar;
// -------
// (int *) foo;
// (my_custom_type_that_was_not_passed_with_T_argument_see_below *)bar;
// -------
--space-after-cast
//
// -------
// sizeof(foobar)
// -------
// sizeof (foobar)
// -------
-bs
//
// -------
// for(foo;bar;baz)
// -------
// for (foo;bar;baz)
// -------
--space-after-for
//
// -------
// if(foo)
// -------
// if (foo)
// -------
--space-after-if
//
// -------
// while(foo)
// -------
// while (foo)
// -------
--space-after-while
//
// -------
// if ( foo ( a > b ) | ( bar ( baz ) ) )
// -------
// if (foo (a > b) | (bar (baz)))
// -------
--no-space-after-parentheses
//
// -------
// int     a;
// char  b;
// -------
// int a;
// char b;
// -------
--declaration-indentation0
//
// -------
// int a,
//  b,
//  c;
// -------
// int a, b, c;
// -------
--no-blank-lines-after-commas
//
// -------
// int foo (int bar, char *baz, long wheee, intptr_t zool);
// -------
// int foo (
//     int bar,
//     char *baz,
//     long wheee,
//     intptr_t zool);
// -------
--break-function-decl-args
//
// -------
// int foo (
//     int bar,
//     char *baz,
//     long wheee,
//     intptr_t zool
//     );
// -------
// int foo (
//     int bar,
//     char *baz,
//     long wheee,
//     intptr_t zool);
// -------
--dont-break-function-decl-args-end
//
// -------
// int foo (bar);
// -------
// int
// foo (bar);
// -------
--procnames-start-lines
//
// -------
// struct foo { int a; };
// -------
// struct foo
// {
//   int a;
// };
// -------
--braces-after-struct-decl-line
//
// -------
// int foo (bar) {
//   baz
// }
// -------
// int foo (bar)
// {
//   baz
// }
// -------
--braces-after-func-def-line
//
// -------
// if (foo)
// {
// while (bar)
// {
// baz;
// }
// }
// -------
// if (foo)
// {
//   while (bar)
//   {
//     baz;
//   }
// }
// -------
--indent-level2
//
// -------
// if (foo)
//   {
//     bar;
//   }
// -------
// if (foo)
// {
//   bar;
// }
// -------
--brace-indent0
//
// -------
// boom = foo (bar) - baz +
//   whee (zool);
// rules = power (mono, mwahahahahahahahaahahahahahahahahahahhahahahahaha,
// stereo);
// -------
// boom = foo (bar) - baz +
//     whee (zool);
// rules = power (mono, mwahahahahahahahaahahahahahahahahahahhahahahahaha,
//     stereo);
// -------
--continuation-indentation4
//
// -------
// rules = power (mono, mwahahahahahahahaahahahahahahahahahahhahahahahaha,
// stereo);
// -------
// rules = power (mono, mwahahahahahahahaahahahahahahahahahahhahahahahaha,
//                stereo);
// -------
--continue-at-parentheses
//--dont-line-up-parentheses
//
// -------
// while ((((i < 2 &&
//         k > 0) || p == 0) &&
//     q == 1) ||
//   n = 0)
// -------
// while ((((i < 2 &&
//     k > 0) || p == 0) &&
//     q == 1) ||
//     n = 0)
// -------
--paren-indentation2
//
// -------
// char *
// create_world (x, y, scale)
// int x;
// int y;
// float scale;
// {
//   ...
// }
// -------
// char *
// create_world (x, y, scale)
//   int x;
//   int y;
//   float scale;
// {
//   ...
// }
// -------
--parameter-indentation2
//
// -------
// if (longlonglonglonglonglonglong
// <tab character>short)
// -------
// if (longlonglonglonglonglonglong
//      short)
// -------
--no-tabs
//
// -------
// #if WINDOWS
// #if ZOOL
// #define WHEE GNUNET_NO
// #else
// #define WHEE GNUNET_YES
// #endif
// #endif
// -------
// #if WINDOWS
// #  if ZOOL
// #    define WHEE GNUNET_NO
// #  else
// #    define WHEE GNUNET_YES
// #  endif
// #endif
// -------
--preprocessor-indentation0
//
// -------
// int foo (bar)
// {
//   if (c)
//     goto end;
//   if (a > 0)
//   {
//     begin:
//     a = 0;
//     if (b != 0)
//       goto begin;
//   }
//   end:
//   return 0;
// }
// -------
// int foo (bar)
// {
//   if (c)
//     goto end;
//   if (a > 0)
//   {
// begin:
//     a = 0;
//     if (b != 0)
//       goto begin;
//   }
// end:
//   return 0;
// }
// -------
--indent-label0
//
// -------
// line-longer-than-80-chars /* some comment, not counted */
// -------
// 80-chars-long-line /* some comment, not counted */
// rest-of-the-line
// -------
--line-length80
//
// -------
// /* comment-line-longer-than-80-chars */
// -------
// /* 80-chars-long-comment-line
//    rest-of-the-line */
// -------
--comment-line-length80
//
// -------
// if (mask
//     && ((mask[0] == '\0')
//     || (mask[1] == '\0'
//     && ((mask[0] == '0') || (mask[0] == '*')))))
// -------
// if (mask &&
//     ((mask[0] == '\0') ||
//     (mask[1] == '\0' &&
//     ((mask[0] == '0') || (mask[0] == '*')))))
// -------
--break-after-boolean-operator
//
// -------
// if (mask
//     && ((mask[0] == '\0')
//     || (mask[1] == '\0' && ((mask[0] == '0') || (mask[0] == '*')))))
// -------
// if (mask  /* this newline is preserved, override it with --ignore-newlines */
//     && ((mask[0] == '\0')
//         || (mask[1] == '\0' &&
//             ((mask[0] == '0') || (mask[0] == '*')))))
// -------
// For now just keep ignoring. After everything settles down, we might want to start putting custom newlines where it is appropriate
// --honour-newlines
--ignore-newlines
//
//
//
// Also add a list of typedefed types here, like this:
// -T <typedefedtype1>
// -T <typedefedtype2>
// for this:
// typedef int typedefedtype1;
// typedef char *typedefedtype2;
// The following is obtained by running a Python script i wrote on src subdir:
-T GNUNET_MysqlDataProcessor
-T GNUNET_DHT_MessageReceivedHandler
-T DHTLOG_MESSAGE_TYPES
-T GNUNET_MysqlDataProcessor
-T GNUNET_DV_MessageReceivedHandler
-T p2p_dv_MESSAGE_NeighborInfo
-T p2p_dv_MESSAGE_Data
-T p2p_dv_MESSAGE_Disconnect
-T GNUNET_FS_QueueStart
-T GNUNET_FS_QueueStop
-T SuspendSignalFunction
-T GNUNET_FS_TEST_UriContinuation
-T GNUNET_FS_TreeBlockProcessor
-T GNUNET_FS_TreeProgressCallback
-T GSF_ConnectedPeerIterator
-T GSF_GetMessageCallback
-T GSF_PeerReserveCallback
-T GSF_PendingRequestReplyHandler
-T GSF_PendingRequestIterator
-T GSF_LocalLookupContinuation
-T GNUNET_ARM_Callback
-T GNUNET_TRANSPORT_ATS_AllocationNotification
-T GNUNET_ATS_AddressSuggestionCallback
-T GNUNET_BLOCK_GetKeyFunction
-T GNUNET_CHAT_JoinCallback
-T GNUNET_CHAT_MessageCallback
-T GNUNET_CHAT_MemberListCallback
-T GNUNET_CHAT_MessageConfirmation
-T GNUNET_CHAT_RoomIterator
-T GNUNET_CLIENT_MessageHandler
-T GNUNET_CLIENT_ShutdownTask
-T GNUNET_FileNameCallback
-T GNUNET_CONFIGURATION_Iterator
-T GNUNET_CONFIGURATION_Section_Iterator
-T GNUNET_CONNECTION_AccessCheck
-T GNUNET_CONNECTION_Receiver
-T GNUNET_CONNECTION_TransmitReadyNotify
-T GNUNET_HashCodeIterator
-T GNUNET_CONTAINER_HashMapIterator
-T GNUNET_CONTAINER_HeapCostType
-T GNUNET_CONTAINER_HeapIterator
-T GNUNET_CORE_ConnectEventHandler
-T GNUNET_CORE_PeerStatusEventHandler
-T GNUNET_CORE_DisconnectEventHandler
-T GNUNET_CORE_MessageCallback
-T GNUNET_CORE_StartupCallback
-T GNUNET_CORE_ControlContinuation
-T GNUNET_CORE_PeerConfigurationInfoCallback
-T GNUNET_CRYPTO_HashCompletedCallback
-T GNUNET_DATACACHE_Iterator
-T GNUNET_DATACACHE_DeleteNotifyCallback
-T DiskUtilizationChange
-T PluginDatumProcessor
-T PluginGetRandom
-T GNUNET_DATASTORE_ContinuationWithStatus
-T GNUNET_DATASTORE_DatumProcessor
-T GNUNET_DHT_GetIterator
-T GNUNET_DHT_FindPeerProcessor
-T GNUNET_DHT_ReplyProcessor
-T GNUNET_DISK_DirectoryIteratorCallback
-T GNUNET_FRAGMENT_MessageProcessor
-T GNUNET_DEFRAGMENT_AckProcessor
-T GNUNET_FS_KeywordIterator
-T GNUNET_FS_ProgressCallback
-T GNUNET_FS_FileInformationProcessor
-T GNUNET_FS_DataReader
-T GNUNET_FS_FileProcessor
-T GNUNET_FS_DirectoryScanner
-T GNUNET_FS_PublishContinuation
-T GNUNET_FS_IndexedFileProcessor
-T GNUNET_FS_NamespaceInfoProcessor
-T GNUNET_FS_IdentifierProcessor
-T GNUNET_FS_DirectoryEntryProcessor
-T GNUNET_HELLO_GenerateAddressListCallback
-T GNUNET_HELLO_AddressIterator
-T GNUNET_MESH_MessageCallback
-T GNUNET_MESH_TunnelEndHandler
-T GNUNET_MESH_ApplicationType
-T GNUNET_MESH_TunnelDisconnectHandler
-T GNUNET_MESH_TunnelConnectHandler
-T GNUNET_MESH_MessageCallback
-T GNUNET_MESH_TunnelEndHandler
-T GNUNET_MESH_ApplicationType
-T GNUNET_MESH_TunnelDisconnectHandler
-T GNUNET_MESH_TunnelConnectHandler
-T GNUNET_NAT_AddressCallback
-T GNUNET_NAT_ReversalCallback
-T GNUNET_NAT_TestCallback
-T GNUNET_NSE_Callback
-T GNUNET_OS_NetworkInterfaceProcessor
-T GNUNET_OS_LineProcessor
-T GNUNET_PEERINFO_Processor
-T GNUNET_PEER_Id
-T GNUNET_PLUGIN_Callback
-T GNUNET_PROGRAM_Main
-T GNUNET_PSEUDONYM_Iterator
-T GNUNET_RESOLVER_AddressCallback
-T GNUNET_RESOLVER_HostnameCallback
-T GNUNET_SCHEDULER_TaskIdentifier
-T GNUNET_SCHEDULER_Task
-T GNUNET_SCHEDULER_select
-T GNUNET_SERVER_MessageCallback
-T GNUNET_SERVER_DisconnectCallback
-T GNUNET_SERVER_MessageTokenizerCallback
-T GNUNET_SERVICE_Main
-T GNUNET_SIGNAL_Handler
-T GNUNET_STATISTICS_Iterator
-T GNUNET_STATISTICS_Callback
-T GNUNET_TESTING_NotifyHostkeyCreated
-T GNUNET_TESTING_NotifyDaemonRunning
-T GNUNET_TESTING_NotifyCompletion
-T GNUNET_TESTING_NotifyConnections
-T GNUNET_TESTING_NotifyConnection
-T GNUNET_TESTING_NotifyTopology
-T GNUNET_TESTING_STATISTICS_Iterator
-T GNUNET_TRANSPORT_SessionEnd
-T GNUNET_TRANSPORT_AddressNotification
-T GNUNET_TRANSPORT_TransmitContinuation
-T GNUNET_TRANSPORT_TransmitFunction
-T GNUNET_TRANSPORT_DisconnectFunction
-T GNUNET_TRANSPORT_AddressStringCallback
-T GNUNET_TRANSPORT_AddressPrettyPrinter
-T GNUNET_TRANSPORT_CheckAddress
-T GNUNET_TRANSPORT_AddressToString
-T GNUNET_TRANSPORT_ReceiveCallback
-T GNUNET_TRANSPORT_NotifyConnect
-T GNUNET_TRANSPORT_NotifyDisconnect
-T GNUNET_TRANSPORT_AddressLookUpCallback
-T GNUNET_TRANSPORT_HelloUpdateCallback
-T GNUNET_TRANSPORT_BlacklistCallback
-T sa_family_t
-T SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
-T PLIBC_SEARCH__compar_fn_t
-T _win_comparison_fn_t
-T PLIBC_SEARCH_ACTION
-T PLIBC_SEARCH_VISIT
-T PLIBC_SEARCH__action_fn_t
-T PLIBC_SEARCH__free_fn_t
-T MESH_TunnelNumber
-T TransmissionContinuation
-T GNUNET_TESTING_ConnectionProcessor
-T SetupContinuation
-T glp_prob
-T glp_iocp
-T glp_smcp
-T GNUNET_TRANSPORT_ATS_AddressNotification
-T GNUNET_TRANSPORT_ATS_ResultCallback
-T GST_BlacklistTestContinuation
-T GST_HelloCallback
-T GST_NeighbourSendContinuation
-T GST_NeighbourIterator
-T GST_ValidationAddressCallback
-T u32
-T u16
-T u8
-T __le32
-T EmailAddress
-T SMTPMessage
-T GNUNET_TRANSPORT_TESTING_connect_cb
-T ieee80211_mgt_beacon_t
-T ieee80211_mgt_auth_t
-T u64
-T u32
-T u16
-T u8
-T uLong
-T uLong
-T KBlock_secret_key
-T MyNSGetExecutablePathProto
-T MeshClient
