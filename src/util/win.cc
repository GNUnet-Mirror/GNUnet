/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/win.cc
 * @brief Helper functions for MS Windows in C++
 * @author Nils Durner
 */

#ifndef _WIN_CC
#define _WIN_CC

#include "winproc.h"
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_connection_lib.h"

#include <list>
using namespace std;
#include <ntdef.h>

#ifndef INHERITED_ACE
#define INHERITED_ACE 0x10
#endif

extern "C" {

int plibc_conv_to_win_path(const char *pszUnix, char *pszWindows);

/**
 * Enumerate all network adapters
 */
void EnumNICs(PMIB_IFTABLE *pIfTable, PMIB_IPADDRTABLE *pAddrTable)
{
  DWORD dwSize, dwRet;

  *pIfTable = NULL;

  if (pAddrTable)
    *pAddrTable = NULL;

  if (GNGetIfTable)
  {
    dwSize = dwRet = 0;

    *pIfTable = (MIB_IFTABLE *) GlobalAlloc(GPTR, sizeof(MIB_IFTABLE));

    /* Get size of table */
    if (GNGetIfTable(*pIfTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER)
    {
      GlobalFree(*pIfTable);
      *pIfTable = (MIB_IFTABLE *) GlobalAlloc(GPTR, dwSize);
    }

    if ((dwRet = GNGetIfTable(*pIfTable, &dwSize, 0)) == NO_ERROR &&
      pAddrTable)
    {
      DWORD dwIfIdx, dwSize = sizeof(MIB_IPADDRTABLE);
      *pAddrTable = (MIB_IPADDRTABLE *) GlobalAlloc(GPTR, dwSize);

      /* Make an initial call to GetIpAddrTable to get the
         necessary size */
      if (GNGetIpAddrTable(*pAddrTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER)
      {
        GlobalFree(*pAddrTable);
        *pAddrTable = (MIB_IPADDRTABLE *) GlobalAlloc(GPTR, dwSize);
      }
      GNGetIpAddrTable(*pAddrTable, &dwSize, 0);
    }
  }
}

/**
 * Lists all network interfaces in a combo box
 * Used by the basic GTK configurator
 *
 * @param callback function to call for each NIC
 * @param callback_cls closure for callback
 */
  int ListNICs(void (*callback) (void *, const char *, int), void * callback_cls)
{
  PMIB_IFTABLE pTable;
  PMIB_IPADDRTABLE pAddrTable;
  DWORD dwIfIdx, dwExternalNIC;
  IPAddr theIP;

  /* Determine our external NIC  */
  theIP = inet_addr("192.0.34.166"); /* www.example.com */
  if ((! GNGetBestInterface) ||
      (GNGetBestInterface(theIP, &dwExternalNIC) != NO_ERROR))
  {
    dwExternalNIC = 0;
  }

  /* Enumerate NICs */
  EnumNICs(&pTable, &pAddrTable);

  if (pTable)
  {
    for(dwIfIdx=0; dwIfIdx <= pTable->dwNumEntries; dwIfIdx++)
    {
      char szEntry[1001];
      DWORD dwIP = 0;
      int iItm;
  		PIP_ADAPTER_INFO pAdapterInfo;
  		PIP_ADAPTER_INFO pAdapter = NULL;
  		DWORD dwRetVal = 0;

      /* Get IP-Address */
      int i;
      for(i = 0; i < pAddrTable->dwNumEntries; i++)
      {
        if (pAddrTable->table[i].dwIndex == pTable->table[dwIfIdx].dwIndex)
        {
          dwIP = pAddrTable->table[i].dwAddr;
          break;
        }
      }

      if (dwIP)
      {
        BYTE bPhysAddr[MAXLEN_PHYSADDR];
  		  char *pszIfName = NULL;
        char dst[INET_ADDRSTRLEN];

        /* Get friendly interface name */
  			pAdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof(IP_ADAPTER_INFO));
  			ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

  			/* Make an initial call to GetAdaptersInfo to get
  			   the necessary size into the ulOutBufLen variable */
  			if (GGetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
  			  free(pAdapterInfo);
  			  pAdapterInfo = (IP_ADAPTER_INFO *) malloc (ulOutBufLen);
  			}

  			if ((dwRetVal = GGetAdaptersInfo( pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
  			  pAdapter = pAdapterInfo;
  			  while (pAdapter) {
  			  	if (pTable->table[dwIfIdx].dwIndex == pAdapter->Index)
  			  	{
  			  		char szKey[251];
  			  		long lLen = 250;

  			  		sprintf(szKey, "SYSTEM\\CurrentControlSet\\Control\\Network\\"
  			  			"{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection",
  			  			pAdapter->AdapterName);
  			  		pszIfName = (char *) malloc(251);
  			  		if (QueryRegistry(HKEY_LOCAL_MACHINE, szKey, "Name", pszIfName,
  			  			&lLen) != ERROR_SUCCESS)
  			  		{
  			  			free(pszIfName);
  			  			pszIfName = NULL;
  			  		}
  			  	}
  			    pAdapter = pAdapter->Next;
  			  }
  			}
  			free(pAdapterInfo);

  			/* Set entry */
        memset(bPhysAddr, 0, MAXLEN_PHYSADDR);
        memcpy(bPhysAddr,
          pTable->table[dwIfIdx].bPhysAddr,
          pTable->table[dwIfIdx].dwPhysAddrLen);

        snprintf(szEntry, 1000, "%s (%s - %I64u)",
          pszIfName ? pszIfName : (char *) pTable->table[dwIfIdx].bDescr,
          inet_ntop (AF_INET, &dwIP, dst, INET_ADDRSTRLEN),
          *((unsigned long long *) bPhysAddr));
        szEntry[1000] = 0;

        if (pszIfName)
         	free(pszIfName);

        callback(callback_cls,
		 szEntry, 
		 pAddrTable->table[dwIfIdx].dwIndex == dwExternalNIC);
      }
    }
    GlobalFree(pAddrTable);
    GlobalFree(pTable);
  }

  return GNUNET_YES;
}

/**
 * @brief Installs the Windows service
 * @param servicename name of the service as diplayed by the SCM
 * @param application path to the application binary
 * @param username the name of the service's user account
 * @returns 0 on success
 *          1 if the Windows version doesn't support services
 *          2 if the SCM could not be opened
 *          3 if the service could not be created
 */
int InstallAsService(char *servicename, char *application, char *username)
{
  SC_HANDLE hManager, hService;
  char szEXE[_MAX_PATH + 17] = "\"";
  char *user = NULL;

  if (! GNOpenSCManager)
    return 1;

  plibc_conv_to_win_path(application, szEXE + 1);
  strcat(szEXE, "\" --win-service");
  hManager = GNOpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  if (! hManager)
    return 2;

  if (username)
  {
  	user = (char *) malloc(strlen(username) + 3);
  	sprintf(user, ".\\%s", username);
  }

  hService = GNCreateService(hManager, (LPCTSTR) servicename, (LPCTSTR) servicename, 0,
    SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, (LPCTSTR) szEXE,
    NULL, NULL, NULL, (LPCTSTR) user, (LPCTSTR) username);

  if (user)
    free(user);

  if (! hService)
    return 3;

  GNCloseServiceHandle(hService);

  return 0;
}

/**
 * @brief Uninstall Windows service
 * @param servicename name of the service to delete
 * @returns 0 on success
 *          1 if the Windows version doesn't support services
 *          2 if the SCM could not be openend
 *          3 if the service cannot be accessed
 *          4 if the service cannot be deleted
 */
int UninstallService(char *servicename)
{
  SC_HANDLE hManager, hService;

  if (! GNOpenSCManager)
    return 1;

  hManager = GNOpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
  if (! hManager)
    return 2;

  if (! (hService = GNOpenService(hManager, (LPCTSTR) servicename, DELETE)))
    if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST)
      return 3;
     else
     	goto closeSCM;

  if (! GNDeleteService(hService))
    if (GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE)
      return 4;

closeSCM:
  GNCloseServiceHandle(hService);

  return 0;
}

/**
 * @author Scott Field, Microsoft
 * @see http://support.microsoft.com/?scid=kb;en-us;132958
 * @date 12-Jul-95
 */
void _InitLsaString(PLSA_UNICODE_STRING LsaString, LPWSTR String)
{
  DWORD StringLength;

  if(String == NULL)
  {
    LsaString->Buffer = NULL;
    LsaString->Length = 0;
    LsaString->MaximumLength = 0;
    return;
  }

  StringLength = wcslen(String);
  LsaString->Buffer = String;
  LsaString->Length = (USHORT) StringLength *sizeof(WCHAR);
  LsaString->MaximumLength = (USHORT) (StringLength + 1) * sizeof(WCHAR);
}


/**
 * @author Scott Field, Microsoft
 * @see http://support.microsoft.com/?scid=kb;en-us;132958
 * @date 12-Jul-95
 */
NTSTATUS _OpenPolicy(LPWSTR ServerName, DWORD DesiredAccess, PLSA_HANDLE PolicyHandle)
{
  LSA_OBJECT_ATTRIBUTES ObjectAttributes;
  LSA_UNICODE_STRING ServerString;
  PLSA_UNICODE_STRING Server = NULL;

  /* Always initialize the object attributes to all zeroes. */
  ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

  if(ServerName != NULL)
  {
    /* Make a LSA_UNICODE_STRING out of the LPWSTR passed in */
    _InitLsaString(&ServerString, ServerName);
    Server = &ServerString;
  }

  /* Attempt to open the policy. */
  return GNLsaOpenPolicy(Server,
                       &ObjectAttributes, DesiredAccess, PolicyHandle);
}

/**
 * @brief Obtain a SID representing the supplied account on the supplied system
 * @return TRUE on success, FALSE on failure
 * @author Scott Field, Microsoft
 * @date 12-Jul-95
 * @remarks A buffer is allocated which contains the SID representing the
 *          supplied account. This buffer should be freed when it is no longer
 *          needed by calling\n
 *            HeapFree(GetProcessHeap(), 0, buffer)
 * @remarks Call GetLastError() to obtain extended error information.
 * @see http://support.microsoft.com/?scid=kb;en-us;132958
 */
BOOL _GetAccountSid(LPTSTR SystemName, LPTSTR AccountName, PSID * Sid)
{
  LPTSTR ReferencedDomain = NULL;
  DWORD cbSid = 128;  							/* initial allocation attempt */
  DWORD cchReferencedDomain = 16;  	/* initial allocation size */
  SID_NAME_USE peUse;
  BOOL bSuccess = FALSE;  					/* assume this function will fail */

  /* initial memory allocations */
  if ((*Sid = HeapAlloc (GetProcessHeap (), 0, cbSid)) == NULL)
  	return FALSE;

  if ((ReferencedDomain = (LPTSTR) HeapAlloc (GetProcessHeap (),
  				    0,
  				    cchReferencedDomain *
  				    sizeof (TCHAR))) == NULL)
  	return FALSE;

    /* Obtain the SID of the specified account on the specified system. */
  	while (!GNLookupAccountName(SystemName,	/* machine to lookup account on */
  		   AccountName,												/* account to lookup */
  		   *Sid,															/* SID of interest */
  		   &cbSid,														/* size of SID */
  		   ReferencedDomain,									/* domain account was found on */
  		   &cchReferencedDomain, &peUse))
  	{
  		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
  		{
  			/* reallocate memory */
  			if ((*Sid = HeapReAlloc (GetProcessHeap (), 0, *Sid, cbSid)) == NULL)
  				return FALSE;

  			if ((ReferencedDomain = (LPTSTR) HeapReAlloc (GetProcessHeap (),
  					      0,
  					      ReferencedDomain,
  					      cchReferencedDomain
  					      * sizeof (TCHAR))) == NULL)
  				return FALSE;
      }
      else
        goto end;
  }

  /* Indicate success. */
  bSuccess = TRUE;

end:
  /* Cleanup and indicate failure, if appropriate. */
  HeapFree (GetProcessHeap (), 0, ReferencedDomain);

  if (!bSuccess)
  {
    if (*Sid != NULL)
    {
  		HeapFree (GetProcessHeap (), 0, *Sid);
  		*Sid = NULL;
    }
  }

  return bSuccess;
}

/**
 * @author Scott Field, Microsoft
 * @see http://support.microsoft.com/?scid=kb;en-us;132958
 * @date 12-Jul-95
 */
NTSTATUS _SetPrivilegeOnAccount(LSA_HANDLE PolicyHandle,/* open policy handle */
                               PSID AccountSid,   			/* SID to grant privilege to */
                               LPWSTR PrivilegeName,  	/* privilege to grant (Unicode) */
                               BOOL bEnable  						/* enable or disable */
  )
{
  LSA_UNICODE_STRING PrivilegeString;

  /* Create a LSA_UNICODE_STRING for the privilege name. */
  _InitLsaString(&PrivilegeString, PrivilegeName);

  /* grant or revoke the privilege, accordingly */
  if(bEnable)
  {
    NTSTATUS i;

    i = GNLsaAddAccountRights(PolicyHandle,  				/* open policy handle */
                               AccountSid,        			/* target SID */
                               &PrivilegeString,        /* privileges */
                               1  											/* privilege count */
      );
  }
  else
  {
    return GNLsaRemoveAccountRights(PolicyHandle,  			/* open policy handle */
                                  AccountSid,     			/* target SID */
                                  FALSE,  							/* do not disable all rights */
                                  &PrivilegeString,  		/* privileges */
                                  1  										/* privilege count */
      );
  }
}

/**
 * @brief Create a Windows service account
 * @return 0 on success, > 0 otherwise
 * @param pszName the name of the account
 * @param pszDesc description of the account
 */
int CreateServiceAccount(char *pszName, char *pszDesc)
{
  USER_INFO_1 ui;
  USER_INFO_1008 ui2;
  NET_API_STATUS nStatus;
  wchar_t wszName[MAX_NAME_LENGTH], wszDesc[MAX_NAME_LENGTH];
  DWORD dwErr;
  LSA_HANDLE hPolicy;
  PSID pSID;

  if (! GNNetUserAdd)
  	return 1;
  mbstowcs(wszName, pszName, strlen(pszName) + 1);
  mbstowcs(wszDesc, pszDesc, strlen(pszDesc) + 1);

  memset(&ui, 0, sizeof(ui));
  ui.usri1_name = wszName;
  ui.usri1_password = wszName; /* account is locked anyway */
  ui.usri1_priv = USER_PRIV_USER;
  ui.usri1_comment = wszDesc;
  ui.usri1_flags = UF_SCRIPT;

  nStatus = GNNetUserAdd(NULL, 1, (LPBYTE)&ui, NULL);

  if (nStatus != NERR_Success && nStatus != NERR_UserExists)
  	return 2;

  ui2.usri1008_flags = UF_PASSWD_CANT_CHANGE | UF_DONT_EXPIRE_PASSWD;
  GNNetUserSetInfo(NULL, wszName, 1008, (LPBYTE)&ui2, NULL);

  if (_OpenPolicy(NULL, POLICY_ALL_ACCESS, &hPolicy) !=
  										STATUS_SUCCESS)
  	return 3;

  _GetAccountSid(NULL, (LPTSTR) pszName, &pSID);

  if (_SetPrivilegeOnAccount(hPolicy, pSID, L"SeServiceLogonRight", TRUE) != STATUS_SUCCESS)
  	return 4;

  _SetPrivilegeOnAccount(hPolicy, pSID, L"SeDenyInteractiveLogonRight", TRUE);
  _SetPrivilegeOnAccount(hPolicy, pSID, L"SeDenyBatchLogonRight", TRUE);
  _SetPrivilegeOnAccount(hPolicy, pSID, L"SeDenyNetworkLogonRight", TRUE);

  GNLsaClose(hPolicy);

  return 0;
}

/**
 * @brief Grant permission to a file
 * @param lpszFileName the name of the file or directory
 * @param lpszAccountName the user account
 * @param dwAccessMask the desired access (e.g. GENERIC_ALL)
 * @return TRUE on success
 * @remark based on http://support.microsoft.com/default.aspx?scid=KB;EN-US;Q102102&
 */
BOOL AddPathAccessRights(char *lpszFileName, char *lpszAccountName,
      DWORD dwAccessMask)
{
  /* SID variables. */
  SID_NAME_USE   snuType;
  TCHAR *        szDomain       = NULL;
  DWORD          cbDomain       = 0;
  LPVOID         pUserSID       = NULL;
  DWORD          cbUserSID      = 0;

  /* File SD variables. */
  PSECURITY_DESCRIPTOR pFileSD  = NULL;
  DWORD          cbFileSD       = 0;

  /* New SD variables. */
  SECURITY_DESCRIPTOR  newSD;

  /* ACL variables. */
  PACL           pACL           = NULL;
  BOOL           fDaclPresent;
  BOOL           fDaclDefaulted;
  ACL_SIZE_INFORMATION AclInfo;

  /* New ACL variables. */
  PACL           pNewACL        = NULL;
  DWORD          cbNewACL       = 0;

  /* Temporary ACE. */
  LPVOID         pTempAce       = NULL;
  UINT           CurrentAceIndex = 0;

  UINT           newAceIndex = 0;

  /* Assume function will fail. */
  BOOL           fResult        = FALSE;
  BOOL           fAPISuccess;

  SECURITY_INFORMATION secInfo = DACL_SECURITY_INFORMATION;

  /**
   * STEP 1: Get SID of the account name specified.
   */
  fAPISuccess = GNLookupAccountName(NULL, (LPCTSTR) lpszAccountName,
        pUserSID, &cbUserSID, (LPTSTR) szDomain, &cbDomain, &snuType);

  /* API should have failed with insufficient buffer. */
  if (fAPISuccess)
     goto end;
  else if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
     goto end;
  }

  pUserSID = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbUserSID);
  if (!pUserSID) {
     goto end;
  }

  szDomain = (TCHAR *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbDomain * sizeof(TCHAR));
  if (!szDomain) {
     goto end;
  }

  fAPISuccess = GNLookupAccountName(NULL, (LPCTSTR) lpszAccountName,
        pUserSID, &cbUserSID, (LPTSTR) szDomain, &cbDomain, &snuType);
  if (!fAPISuccess) {
     goto end;
  }

  /**
   *  STEP 2: Get security descriptor (SD) of the file specified.
   */
  fAPISuccess = GNGetFileSecurity((LPCTSTR) lpszFileName,
        secInfo, pFileSD, 0, &cbFileSD);

  /* API should have failed with insufficient buffer. */
  if (fAPISuccess)
     goto end;
  else if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
     goto end;
  }

  pFileSD = (PSECURITY_DESCRIPTOR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
  	cbFileSD);
  if (!pFileSD) {
     goto end;
  }

  fAPISuccess = GNGetFileSecurity((LPCTSTR) lpszFileName,
        secInfo, pFileSD, cbFileSD, &cbFileSD);
  if (!fAPISuccess) {
     goto end;
  }

  /**
   * STEP 3: Initialize new SD.
   */
  if (!GNInitializeSecurityDescriptor(&newSD,
        SECURITY_DESCRIPTOR_REVISION)) {
     goto end;
  }

  /**
   * STEP 4: Get DACL from the old SD.
   */
  if (!GNGetSecurityDescriptorDacl(pFileSD, &fDaclPresent, &pACL,
        &fDaclDefaulted)) {
     goto end;
  }

  /**
   * STEP 5: Get size information for DACL.
   */
  AclInfo.AceCount = 0; // Assume NULL DACL.
  AclInfo.AclBytesFree = 0;
  AclInfo.AclBytesInUse = sizeof(ACL);

  if (pACL == NULL)
     fDaclPresent = FALSE;

  /* If not NULL DACL, gather size information from DACL. */
  if (fDaclPresent) {

     if (!GNGetAclInformation(pACL, &AclInfo,
           sizeof(ACL_SIZE_INFORMATION), AclSizeInformation)) {
        goto end;
     }
  }

  /**
   * STEP 6: Compute size needed for the new ACL.
   */
  cbNewACL = AclInfo.AclBytesInUse + sizeof(ACCESS_ALLOWED_ACE)
        + GetLengthSid(pUserSID) - sizeof(DWORD);

  /**
   * STEP 7: Allocate memory for new ACL.
   */
  pNewACL = (PACL) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbNewACL);
  if (!pNewACL) {
     goto end;
  }

  /**
   * STEP 8: Initialize the new ACL.
   */
  if (!GNInitializeAcl(pNewACL, cbNewACL, ACL_REVISION2)) {
     goto end;
  }

  /**
   * STEP 9 If DACL is present, copy all the ACEs from the old DACL
   * to the new DACL.
   *
   * The following code assumes that the old DACL is
   * already in Windows 2000 preferred order.  To conform
   * to the new Windows 2000 preferred order, first we will
   * copy all non-inherited ACEs from the old DACL to the
   * new DACL, irrespective of the ACE type.
   */

  newAceIndex = 0;

  if (fDaclPresent && AclInfo.AceCount) {

     for (CurrentAceIndex = 0;
           CurrentAceIndex < AclInfo.AceCount;
           CurrentAceIndex++) {

        /**
         * TEP 10: Get an ACE.
         */
        if (!GNGetAce(pACL, CurrentAceIndex, &pTempAce)) {
           goto end;
        }

        /**
         * STEP 11: Check if it is a non-inherited ACE.
         * If it is an inherited ACE, break from the loop so
         * that the new access allowed non-inherited ACE can
         * be added in the correct position, immediately after
         * all non-inherited ACEs.
         */
        if (((ACCESS_ALLOWED_ACE *)pTempAce)->Header.AceFlags
           & INHERITED_ACE)
           break;

        /**
         * STEP 12: Skip adding the ACE, if the SID matches
         * with the account specified, as we are going to
         * add an access allowed ACE with a different access
         * mask.
         */
        if (GNEqualSid(pUserSID,
           &(((ACCESS_ALLOWED_ACE *)pTempAce)->SidStart)))
           continue;

        /**
         * STEP 13: Add the ACE to the new ACL.
         */
        if (!GNAddAce(pNewACL, ACL_REVISION, MAXDWORD, pTempAce,
              ((PACE_HEADER) pTempAce)->AceSize)) {
           goto end;
        }

        newAceIndex++;
     }
  }

  /**
   * STEP 14: Add the access-allowed ACE to the new DACL.
   * The new ACE added here will be in the correct position,
   * immediately after all existing non-inherited ACEs.
   */
  if (!GNAddAccessAllowedAce(pNewACL, ACL_REVISION2, dwAccessMask,
        pUserSID)) {
     goto end;
  }

  /**
   * STEP 14.5: Make new ACE inheritable
   */
  if (!GetAce(pNewACL, newAceIndex, &pTempAce))
    goto end;
  ((ACCESS_ALLOWED_ACE *)pTempAce)->Header.AceFlags |=
    (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE);

  /**
   * STEP 15: To conform to the new Windows 2000 preferred order,
   * we will now copy the rest of inherited ACEs from the
   * old DACL to the new DACL.
   */
  if (fDaclPresent && AclInfo.AceCount) {

     for (;
          CurrentAceIndex < AclInfo.AceCount;
          CurrentAceIndex++) {

        /**
         * STEP 16: Get an ACE.
         */
        if (!GNGetAce(pACL, CurrentAceIndex, &pTempAce)) {
           goto end;
        }

        /**
         * STEP 17: Add the ACE to the new ACL.
         */
        if (!GNAddAce(pNewACL, ACL_REVISION, MAXDWORD, pTempAce,
              ((PACE_HEADER) pTempAce)->AceSize)) {
           goto end;
        }
     }
  }

  /**
   * STEP 18: Set permissions
   */
  if (GNSetNamedSecurityInfo((LPTSTR) lpszFileName, SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION, NULL, NULL, pNewACL, NULL) != ERROR_SUCCESS) {
    	goto end;
  }

  fResult = TRUE;

end:

  /**
   * STEP 19: Free allocated memory
   */
  if (pUserSID)
     HeapFree(GetProcessHeap(), 0, pUserSID);

  if (szDomain)
     HeapFree(GetProcessHeap(), 0, szDomain);

  if (pFileSD)
     HeapFree(GetProcessHeap(), 0, pFileSD);

  if (pNewACL)
     HeapFree(GetProcessHeap(), 0, pNewACL);

  return fResult;
}

char *winErrorStr(const char *prefix, int dwErr)
{
  char *err, *ret;
  int mem;

  if (! FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
    NULL, (DWORD) dwErr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &err,
    0, NULL ))
  {
    err = "";
  }

  mem = strlen(err) + strlen(prefix) + 20;
  ret = (char *) malloc(mem);

  snprintf(ret, mem, "%s: %s (#%u)", prefix, err, dwErr);

  LocalFree(err);

  return ret;
}

} /* extern "C" */

#endif
