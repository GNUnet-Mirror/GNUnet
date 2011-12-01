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
 * @file util/winproc.c
 * @brief Functions for MS Windows
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_common.h"

#define DEBUG_WINPROC 0

#ifdef MINGW

static HINSTANCE hNTDLL, hIphlpapi, hAdvapi, hNetapi;
#ifdef W32_VEH
static void *GNWinVEH_handle = NULL;
#endif

TNtQuerySystemInformation GNNtQuerySystemInformation;
TGetIfEntry GNGetIfEntry;
TGetIpAddrTable GNGetIpAddrTable;
TGetIfTable GNGetIfTable;
TOpenSCManager GNOpenSCManager;
TCreateService GNCreateService;
TCloseServiceHandle GNCloseServiceHandle;
TDeleteService GNDeleteService;
TRegisterServiceCtrlHandler GNRegisterServiceCtrlHandler;
TSetServiceStatus GNSetServiceStatus;
TStartServiceCtrlDispatcher GNStartServiceCtrlDispatcher;
TControlService GNControlService;
TOpenService GNOpenService;
TGetBestInterfaceEx GNGetBestInterfaceEx;
TGetAdaptersInfo GNGetAdaptersInfo;
TNetUserAdd GNNetUserAdd;
TNetUserSetInfo GNNetUserSetInfo;
TLsaOpenPolicy GNLsaOpenPolicy;
TLsaAddAccountRights GNLsaAddAccountRights;
TLsaRemoveAccountRights GNLsaRemoveAccountRights;
TLsaClose GNLsaClose;
TLookupAccountName GNLookupAccountName;
TGetFileSecurity GNGetFileSecurity;
TInitializeSecurityDescriptor GNInitializeSecurityDescriptor;
TGetSecurityDescriptorDacl GNGetSecurityDescriptorDacl;
TGetAclInformation GNGetAclInformation;
TInitializeAcl GNInitializeAcl;
TGetAce GNGetAce;
TEqualSid GNEqualSid;
TAddAce GNAddAce;
TAddAccessAllowedAce GNAddAccessAllowedAce;
TSetNamedSecurityInfo GNSetNamedSecurityInfo;

#define LOG(kind,...) GNUNET_log_from (kind, "winproc", __VA_ARGS__)
/**
 * Log (panic) messages from PlibC
 */
void
plibc_panic (int err, char *msg)
{
  LOG (((err == INT_MAX) ? GNUNET_ERROR_TYPE_DEBUG : GNUNET_ERROR_TYPE_ERROR),
       "%s", msg);
}

#ifdef W32_VEH
/**
 * Handles exceptions (useful for debugging).
 * Issues a DebugBreak() call if the process is being debugged (not really
 * useful - if the process is being debugged, this handler won't be invoked
 * anyway). If it is not, runs a debugger from GNUNET_DEBUGGER env var,
 * substituting first %u in it for PID, and the second one for the event,
 * that should be set once the debugger attaches itself (otherwise the
 * only way out of WaitForSingleObject() is to time out after 1 minute).
 */
LONG __stdcall
GNWinVEH (PEXCEPTION_POINTERS ExceptionInfo)
{
  char debugger[MAX_PATH + 1];
  char *debugger_env = NULL;
  if (IsDebuggerPresent ())
  {
    DebugBreak ();
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  debugger_env = getenv ("GNUNET_DEBUGGER");
  if (debugger_env != NULL)
  {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    HANDLE event;
    SECURITY_ATTRIBUTES sa;
    memset (&si, 0, sizeof (si));
    si.cb = sizeof (si);
    memset (&pi, 0, sizeof (pi));
    memset (&sa, 0, sizeof (sa));
    sa.nLength = sizeof (sa);
    sa.bInheritHandle = TRUE;
    event = CreateEvent (&sa, FALSE, FALSE, NULL);
    snprintf (debugger, MAX_PATH + 1, debugger_env, GetCurrentProcessId (), (uintptr_t) event);
    debugger[MAX_PATH] = '\0';
    if (0 != CreateProcessA (NULL, debugger, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
      CloseHandle (pi.hProcess);
      CloseHandle (pi.hThread);
      WaitForSingleObject (event, 60000);
      CloseHandle (event);
      if (IsDebuggerPresent ())
      {
        return EXCEPTION_CONTINUE_EXECUTION;
      }
    }
    else
      CloseHandle (event);
  }
  return EXCEPTION_CONTINUE_SEARCH;
}
#endif

/**
 * @brief Initialize PlibC and set up Windows environment
 * @param logging context, NULL means stderr
 * @return Error code from winerror.h, ERROR_SUCCESS on success
*/
int
GNInitWinEnv ()
{
  int ret;

  plibc_initialized ();
  plibc_set_panic_proc (plibc_panic);
  ret = plibc_init ("GNU", PACKAGE);

  /* don't load other DLLs twice */
  if (hNTDLL)
    return ret;

#ifdef W32_VEH
  if (GNWinVEH_handle == NULL)
  {
    GNWinVEH_handle = AddVectoredExceptionHandler (1, &GNWinVEH);
    if (GNWinVEH_handle == NULL)
    {
      /* This is bad, but what can we do? */
      printf ("Failed to set up an exception handler!\n");
    }
  }
#endif

  hNTDLL = LoadLibrary ("ntdll.dll");

  /* Function to get CPU usage under Win NT */
  if (hNTDLL)
  {
    GNNtQuerySystemInformation =
        (TNtQuerySystemInformation) GetProcAddress (hNTDLL,
                                                    "NtQuerySystemInformation");
  }
  else
  {
    GNNtQuerySystemInformation = NULL;
  }

  /* Functions to get information about a network adapter */
  hIphlpapi = LoadLibrary ("iphlpapi.dll");
  if (hIphlpapi)
  {
    GNGetIfEntry = (TGetIfEntry) GetProcAddress (hIphlpapi, "GetIfEntry");
    GNGetIpAddrTable =
        (TGetIpAddrTable) GetProcAddress (hIphlpapi, "GetIpAddrTable");
    GNGetIfTable = (TGetIfTable) GetProcAddress (hIphlpapi, "GetIfTable");
    GNGetBestInterfaceEx =
        (TGetBestInterfaceEx) GetProcAddress (hIphlpapi, "GetBestInterfaceEx");
    GNGetAdaptersInfo =
        (TGetAdaptersInfo) GetProcAddress (hIphlpapi, "GetAdaptersInfo");
  }
  else
  {
    GNGetIfEntry = NULL;
    GNGetIpAddrTable = NULL;
    GNGetIfTable = NULL;
    GNGetBestInterfaceEx = NULL;
    GNGetAdaptersInfo = NULL;
  }

  /* Service & Account functions */
  hAdvapi = LoadLibrary ("advapi32.dll");
  if (hAdvapi)
  {
    GNOpenSCManager =
        (TOpenSCManager) GetProcAddress (hAdvapi, "OpenSCManagerA");
    GNCreateService =
        (TCreateService) GetProcAddress (hAdvapi, "CreateServiceA");
    GNCloseServiceHandle =
        (TCloseServiceHandle) GetProcAddress (hAdvapi, "CloseServiceHandle");
    GNDeleteService =
        (TDeleteService) GetProcAddress (hAdvapi, "DeleteService");
    GNRegisterServiceCtrlHandler =
        (TRegisterServiceCtrlHandler) GetProcAddress (hAdvapi,
                                                      "RegisterServiceCtrlHandlerA");
    GNSetServiceStatus =
        (TSetServiceStatus) GetProcAddress (hAdvapi, "SetServiceStatus");
    GNStartServiceCtrlDispatcher =
        (TStartServiceCtrlDispatcher) GetProcAddress (hAdvapi,
                                                      "StartServiceCtrlDispatcherA");
    GNControlService =
        (TControlService) GetProcAddress (hAdvapi, "ControlService");
    GNOpenService = (TOpenService) GetProcAddress (hAdvapi, "OpenServiceA");

    GNLsaOpenPolicy =
        (TLsaOpenPolicy) GetProcAddress (hAdvapi, "LsaOpenPolicy");
    GNLsaAddAccountRights =
        (TLsaAddAccountRights) GetProcAddress (hAdvapi, "LsaAddAccountRights");
    GNLsaRemoveAccountRights =
        (TLsaRemoveAccountRights) GetProcAddress (hAdvapi,
                                                  "LsaRemoveAccountRights");
    GNLsaClose = (TLsaClose) GetProcAddress (hAdvapi, "LsaClose");
    GNLookupAccountName =
        (TLookupAccountName) GetProcAddress (hAdvapi, "LookupAccountNameA");

    GNGetFileSecurity =
        (TGetFileSecurity) GetProcAddress (hAdvapi, "GetFileSecurityA");
    GNInitializeSecurityDescriptor =
        (TInitializeSecurityDescriptor) GetProcAddress (hAdvapi,
                                                        "InitializeSecurityDescriptor");
    GNGetSecurityDescriptorDacl =
        (TGetSecurityDescriptorDacl) GetProcAddress (hAdvapi,
                                                     "GetSecurityDescriptorDacl");
    GNGetAclInformation =
        (TGetAclInformation) GetProcAddress (hAdvapi, "GetAclInformation");
    GNInitializeAcl =
        (TInitializeAcl) GetProcAddress (hAdvapi, "InitializeAcl");
    GNGetAce = (TGetAce) GetProcAddress (hAdvapi, "GetAce");
    GNEqualSid = (TEqualSid) GetProcAddress (hAdvapi, "EqualSid");
    GNAddAce = (TAddAce) GetProcAddress (hAdvapi, "AddAce");
    GNAddAccessAllowedAce =
        (TAddAccessAllowedAce) GetProcAddress (hAdvapi, "AddAccessAllowedAce");
    GNSetNamedSecurityInfo =
        (TSetNamedSecurityInfo) GetProcAddress (hAdvapi,
                                                "SetNamedSecurityInfoA");
  }
  else
  {
    GNOpenSCManager = NULL;
    GNCreateService = NULL;
    GNCloseServiceHandle = NULL;
    GNDeleteService = NULL;
    GNRegisterServiceCtrlHandler = NULL;
    GNSetServiceStatus = NULL;
    GNStartServiceCtrlDispatcher = NULL;
    GNControlService = NULL;
    GNOpenService = NULL;

    GNLsaOpenPolicy = NULL;
    GNLsaAddAccountRights = NULL;
    GNLsaRemoveAccountRights = NULL;
    GNLsaClose = NULL;
    GNLookupAccountName = NULL;

    GNGetFileSecurity = NULL;
    GNInitializeSecurityDescriptor = NULL;
    GNGetSecurityDescriptorDacl = NULL;
    GNGetAclInformation = NULL;
    GNInitializeAcl = NULL;
    GNGetAce = NULL;
    GNEqualSid = NULL;
    GNAddAce = NULL;
    GNAddAccessAllowedAce = NULL;
    GNSetNamedSecurityInfo = NULL;
  }

  /* Account function */
  hNetapi = LoadLibrary ("netapi32.dll");
  if (hNetapi)
  {
    GNNetUserAdd = (TNetUserAdd) GetProcAddress (hNetapi, "NetUserAdd");
    GNNetUserSetInfo =
        (TNetUserSetInfo) GetProcAddress (hNetapi, "NetUserSetInfo");
  }
  else
  {
    GNNetUserAdd = NULL;
    GNNetUserSetInfo = NULL;
  }

  return ret;
}

/**
 * Clean up Windows environment
 */
void
GNShutdownWinEnv ()
{
  plibc_shutdown ();

#ifdef W32_VEH
  if (GNWinVEH_handle != NULL)
  {
    RemoveVectoredExceptionHandler (GNWinVEH_handle);
    GNWinVEH_handle = NULL;
  }
#endif

  FreeLibrary (hNTDLL);
  FreeLibrary (hIphlpapi);
  FreeLibrary (hAdvapi);
  FreeLibrary (hNetapi);

  CoUninitialize ();
}

#endif /* MINGW */

#if !HAVE_ATOLL
long long
atoll (const char *nptr)
{
  return atol (nptr);
}
#endif
