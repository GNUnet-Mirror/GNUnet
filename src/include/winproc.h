/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file include/winproc.h
 * @brief Definitions for MS Windows
 * @author Nils Durner
 */

#ifndef _WINPROC_H
#define _WINPROC_H

#include <io.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/timeb.h>
#include <time.h>
#include <dirent.h>
#ifndef FD_SETSIZE
#define FD_SETSIZE 1024
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winerror.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <objbase.h>
#include <sys/param.h>          /* #define BYTE_ORDER */
#include <ntsecapi.h>
#include <lm.h>
#include <aclapi.h>


#ifdef __cplusplus
extern "C"
{
#endif

#ifndef MAX_NAME_LENGTH
#define MAX_NAME_LENGTH 25
#endif

  typedef DWORD WINAPI (*TNtQuerySystemInformation) (int, PVOID, ULONG, PULONG);
  typedef DWORD WINAPI (*TGetIfEntry) (PMIB_IFROW pIfRow);
  typedef DWORD WINAPI (*TGetIpAddrTable) (PMIB_IPADDRTABLE pIpAddrTable,
                                           PULONG pdwSize, BOOL bOrder);
  typedef DWORD WINAPI (*TGetIfTable) (PMIB_IFTABLE pIfTable, PULONG pdwSize,
                                       BOOL bOrder);
  typedef DWORD WINAPI (*TGetBestInterfaceEx) (struct sockaddr *, PDWORD);
  /* TODO: Explicitly import -A variants (i.e. TCreateHardLinkA) or -W
   * variants (TCreateHardLinkW), etc.
   */
  typedef DWORD WINAPI (*TCreateHardLink) (LPCTSTR lpFileName,
                                           LPCTSTR lpExistingFileName,
                                           LPSECURITY_ATTRIBUTES
                                           lpSecurityAttributes);
  typedef SC_HANDLE WINAPI (*TOpenSCManager) (LPCTSTR lpMachineName,
                                              LPCTSTR lpDatabaseName,
                                              DWORD dwDesiredAccess);
  typedef SC_HANDLE WINAPI (*TCreateService) (SC_HANDLE hSCManager,
                                              LPCTSTR lpServiceName,
                                              LPCTSTR lpDisplayName,
                                              DWORD dwDesiredAccess,
                                              DWORD dwServiceType,
                                              DWORD dwStartType,
                                              DWORD dwErrorControl,
                                              LPCTSTR lpBinaryPathName,
                                              LPCTSTR lpLoadOrderGroup,
                                              LPDWORD lpdwTagId,
                                              LPCTSTR lpDependencies,
                                              LPCTSTR lpServiceStartName,
                                              LPCTSTR lpPassword);
  typedef BOOL WINAPI (*TCloseServiceHandle) (SC_HANDLE hSCObject);
  typedef BOOL WINAPI (*TDeleteService) (SC_HANDLE hService);
  typedef SERVICE_STATUS_HANDLE WINAPI (*TRegisterServiceCtrlHandler) (LPCTSTR
                                                                       lpServiceName,
                                                                       LPHANDLER_FUNCTION
                                                                       lpHandlerProc);
  typedef BOOL WINAPI (*TSetServiceStatus) (SERVICE_STATUS_HANDLE
                                            hServiceStatus,
                                            LPSERVICE_STATUS lpServiceStatus);
  typedef BOOL WINAPI (*TStartServiceCtrlDispatcher) (const
                                                      LPSERVICE_TABLE_ENTRY
                                                      lpServiceTable);
  typedef BOOL WINAPI (*TControlService) (SC_HANDLE hService, DWORD dwControl,
                                          LPSERVICE_STATUS lpServiceStatus);
  typedef SC_HANDLE WINAPI (*TOpenService) (SC_HANDLE hSCManager,
                                            LPCTSTR lpServiceName,
                                            DWORD dwDesiredAccess);
  typedef DWORD WINAPI (*TGetAdaptersInfo) (PIP_ADAPTER_INFO pAdapterInfo,
                                            PULONG pOutBufLen);
  typedef NET_API_STATUS WINAPI (*TNetUserAdd) (LPCWSTR, DWORD, PBYTE, PDWORD);
  typedef NET_API_STATUS WINAPI (*TNetUserSetInfo) (LPCWSTR servername,
                                                    LPCWSTR username,
                                                    DWORD level, LPBYTE buf,
                                                    LPDWORD parm_err);
  typedef NTSTATUS NTAPI (*TLsaOpenPolicy) (PLSA_UNICODE_STRING,
                                            PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK,
                                            PLSA_HANDLE);
  typedef NTSTATUS NTAPI (*TLsaAddAccountRights) (LSA_HANDLE, PSID,
                                                  PLSA_UNICODE_STRING, ULONG);
  typedef NTSTATUS NTAPI (*TLsaRemoveAccountRights) (LSA_HANDLE, PSID, BOOLEAN,
                                                     PLSA_UNICODE_STRING,
                                                     ULONG);
  typedef NTSTATUS NTAPI (*TLsaClose) (LSA_HANDLE);
  typedef BOOL WINAPI (*TLookupAccountName) (LPCTSTR lpSystemName,
                                             LPCTSTR lpAccountName, PSID Sid,
                                             LPDWORD cbSid,
                                             LPTSTR ReferencedDomainName,
                                             LPDWORD cchReferencedDomainName,
                                             PSID_NAME_USE peUse);

  typedef BOOL WINAPI (*TGetFileSecurity) (LPCTSTR lpFileName,
                                           SECURITY_INFORMATION
                                           RequestedInformation,
                                           PSECURITY_DESCRIPTOR
                                           pSecurityDescriptor, DWORD nLength,
                                           LPDWORD lpnLengthNeeded);
  typedef BOOL WINAPI (*TInitializeSecurityDescriptor) (PSECURITY_DESCRIPTOR
                                                        pSecurityDescriptor,
                                                        DWORD dwRevision);
  typedef BOOL WINAPI (*TGetSecurityDescriptorDacl) (PSECURITY_DESCRIPTOR
                                                     pSecurityDescriptor,
                                                     LPBOOL lpbDaclPresent,
                                                     PACL * pDacl,
                                                     LPBOOL lpbDaclDefaulted);
  typedef BOOL WINAPI (*TGetAclInformation) (PACL pAcl, LPVOID pAclInformation,
                                             DWORD nAclInformationLength,
                                             ACL_INFORMATION_CLASS
                                             dwAclInformationClass);
  typedef BOOL WINAPI (*TInitializeAcl) (PACL pAcl, DWORD nAclLength,
                                         DWORD dwAclRevision);
  typedef BOOL WINAPI (*TGetAce) (PACL pAcl, DWORD dwAceIndex, LPVOID * pAce);
  typedef BOOL WINAPI (*TEqualSid) (PSID pSid1, PSID pSid2);
  typedef BOOL WINAPI (*TAddAce) (PACL pAcl, DWORD dwAceRevision,
                                  DWORD dwStartingAceIndex, LPVOID pAceList,
                                  DWORD nAceListLength);
  typedef BOOL WINAPI (*TAddAccessAllowedAce) (PACL pAcl, DWORD dwAceRevision,
                                               DWORD AccessMask, PSID pSid);
  typedef BOOL WINAPI (*TSetNamedSecurityInfo) (LPTSTR pObjectName,
                                                SE_OBJECT_TYPE ObjectType,
                                                SECURITY_INFORMATION
                                                SecurityInfo, PSID psidOwner,
                                                PSID psidGroup, PACL pDacl,
                                                PACL pSacl);

  extern TGetBestInterfaceEx GNGetBestInterfaceEx;
  extern TNtQuerySystemInformation GNNtQuerySystemInformation;
  extern TGetIfEntry GNGetIfEntry;
  extern TGetIpAddrTable GNGetIpAddrTable;
  extern TGetIfTable GNGetIfTable;
  extern TCreateHardLink GNCreateHardLink;
  extern TOpenSCManager GNOpenSCManager;
  extern TCreateService GNCreateService;
  extern TCloseServiceHandle GNCloseServiceHandle;
  extern TDeleteService GNDeleteService;
  extern TRegisterServiceCtrlHandler GNRegisterServiceCtrlHandler;
  extern TSetServiceStatus GNSetServiceStatus;
  extern TStartServiceCtrlDispatcher GNStartServiceCtrlDispatcher;
  extern TControlService GNControlService;
  extern TOpenService GNOpenService;
  extern TGetAdaptersInfo GNGetAdaptersInfo;
  extern TNetUserAdd GNNetUserAdd;
  extern TNetUserSetInfo GNNetUserSetInfo;
  extern TLsaOpenPolicy GNLsaOpenPolicy;
  extern TLsaAddAccountRights GNLsaAddAccountRights;
  extern TLsaRemoveAccountRights GNLsaRemoveAccountRights;
  extern TLsaClose GNLsaClose;
  extern TLookupAccountName GNLookupAccountName;
  extern TGetFileSecurity GNGetFileSecurity;
  extern TInitializeSecurityDescriptor GNInitializeSecurityDescriptor;
  extern TGetSecurityDescriptorDacl GNGetSecurityDescriptorDacl;
  extern TGetAclInformation GNGetAclInformation;
  extern TInitializeAcl GNInitializeAcl;
  extern TGetAce GNGetAce;
  extern TEqualSid GNEqualSid;
  extern TAddAce GNAddAce;
  extern TAddAccessAllowedAce GNAddAccessAllowedAce;
  extern TSetNamedSecurityInfo GNSetNamedSecurityInfo;


  BOOL CreateShortcut (const char *pszSrc, const char *pszDest);
  BOOL DereferenceShortcut (char *pszShortcut);
  long QueryRegistry (HKEY hMainKey, const char *pszKey, const char *pszSubKey,
                      char *pszBuffer, long *pdLength);
  int ListNICs (void (*callback) (void *, const char *, int), void *cls);
  BOOL AddPathAccessRights (char *lpszFileName, char *lpszAccountName,
                            DWORD dwAccessMask);
  char *winErrorStr (const char *prefix, int dwErr);
  void EnumNICs (PMIB_IFTABLE * pIfTable, PMIB_IPADDRTABLE * pAddrTable);

#define ENUMNICS3_MASK_OK 0x01
#define ENUMNICS3_BCAST_OK 0x02

  struct EnumNICs3_results
  {
    unsigned char flags;
    int is_default;
    char pretty_name[1001];
    size_t addr_size;
    SOCKADDR_STORAGE address;
    SOCKADDR_STORAGE mask;
    SOCKADDR_STORAGE broadcast;
  };

  int EnumNICs3 (struct EnumNICs3_results **, int *EnumNICs3_results_count);
  void EnumNICs3_free (struct EnumNICs3_results *);
  int GNInitWinEnv ();
  void GNShutdownWinEnv ();

#ifdef __cplusplus
}
#endif

#endif
