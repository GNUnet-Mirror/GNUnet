/*
     This file is part of GNUnet
     Copyright (C) 2010 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License, or
     (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file src/util/gnunet-timeout-w32.c
 * @brief small tool starting a child process, waiting that it terminates or killing it after a given timeout period
 * @author LRN
 */

#include <windows.h>
#include <sys/types.h>
#include <stdio.h>

int
main (int argc, char *argv[])
{
  int i;
  DWORD wait_result;
  wchar_t *commandline;
  wchar_t **wargv;
  wchar_t *arg;
  unsigned int cmdlen;
  STARTUPINFOW start;
  PROCESS_INFORMATION proc;

  wchar_t wpath[MAX_PATH + 1];

  wchar_t *pathbuf;
  DWORD pathbuf_len, alloc_len;
  wchar_t *ptr;
  wchar_t *non_const_filename;
  wchar_t *wcmd;
  int wargc;
  int timeout = 0;
  ssize_t wrote;

  HANDLE job;

  if (argc < 3)
    {
      printf
	("arg 1: timeout in sec., arg 2: executable, arg<n> arguments\n");
      exit (1);
    }

  timeout = atoi (argv[1]);

  if (timeout == 0)
    timeout = 600;

  commandline =  GetCommandLineW ();
  if (commandline == NULL)
  {
    printf ("Failed to get commandline: %lu\n", GetLastError ());
    exit (2);
  }

  wargv = CommandLineToArgvW (commandline, &wargc);
  if (wargv == NULL || wargc <= 1)
  {
    printf ("Failed to get parse commandline: %lu\n", GetLastError ());
    exit (3);
  }

  job = CreateJobObject (NULL, NULL);
  if (job == NULL)
  {
    printf ("Failed to create a job: %lu\n", GetLastError ());
    exit (4);
  }

  pathbuf_len = GetEnvironmentVariableW (L"PATH", (wchar_t *) &pathbuf, 0);

  alloc_len = pathbuf_len + 1;

  pathbuf = malloc (alloc_len * sizeof (wchar_t));

  ptr = pathbuf;

  alloc_len = GetEnvironmentVariableW (L"PATH", ptr, pathbuf_len);

  cmdlen = wcslen (wargv[2]);
  if (cmdlen < 5 || wcscmp (&wargv[2][cmdlen - 4], L".exe") != 0)
  {
    non_const_filename = malloc (sizeof (wchar_t) * (cmdlen + 5));
    swprintf (non_const_filename, cmdlen + 5, L"%S.exe", wargv[2]);
  }
  else
  {
    non_const_filename = wcsdup (wargv[2]);
  }

  /* Check that this is the full path. If it isn't, search. */
  if (non_const_filename[1] == L':')
    swprintf (wpath, sizeof (wpath) / sizeof (wchar_t), L"%S", non_const_filename);
  else if (!SearchPathW
           (pathbuf, non_const_filename, NULL, sizeof (wpath) / sizeof (wchar_t),
            wpath, NULL))
  {
    printf ("Failed to get find executable: %lu\n", GetLastError ());
    exit (5);
  }
  free (pathbuf);
  free (non_const_filename);

  cmdlen = wcslen (wpath) + 4;
  i = 3;
  while (NULL != (arg = wargv[i++]))
    cmdlen += wcslen (arg) + 4;

  wcmd = malloc (sizeof (wchar_t) * (cmdlen + 1));
  wrote = 0;
  i = 2;
  while (NULL != (arg = wargv[i++]))
  {
    /* This is to escape trailing slash */
    wchar_t arg_lastchar = arg[wcslen (arg) - 1];
    if (wrote == 0)
    {
      wrote += swprintf (&wcmd[wrote], cmdlen + 1 - wrote, L"\"%S%S\" ", wpath,
          arg_lastchar == L'\\' ? L"\\" : L"");
    }
    else
    {
      if (wcschr (arg, L' ') != NULL)
        wrote += swprintf (&wcmd[wrote], cmdlen + 1 - wrote, L"\"%S%S\"%S", arg,
            arg_lastchar == L'\\' ? L"\\" : L"", i == wargc ? L"" : L" ");
      else
        wrote += swprintf (&wcmd[wrote], cmdlen + 1 - wrote, L"%S%S%S", arg,
            arg_lastchar == L'\\' ? L"\\" : L"", i == wargc ? L"" : L" ");
    }
  }

  LocalFree (wargv);

  memset (&start, 0, sizeof (start));
  start.cb = sizeof (start);

  if (!CreateProcessW (wpath, wcmd, NULL, NULL, TRUE, CREATE_SUSPENDED,
       NULL, NULL, &start, &proc))
  {
    wprintf (L"Failed to get spawn process `%S' with arguments `%S': %lu\n", wpath, wcmd, GetLastError ());
    exit (6);
  }

  AssignProcessToJobObject (job, proc.hProcess);

  ResumeThread (proc.hThread);
  CloseHandle (proc.hThread);

  free (wcmd);

  wait_result = WaitForSingleObject (proc.hProcess, timeout * 1000);
  if (wait_result == WAIT_OBJECT_0)
  {
    DWORD status;
    wait_result = GetExitCodeProcess (proc.hProcess, &status);
    CloseHandle (proc.hProcess);
    if (wait_result != 0)
    {
      printf ("Test process exited with result %lu\n", status);
      TerminateJobObject (job, status);
      exit (status);
    }
    printf ("Test process exited (failed to obtain exit status)\n");
    TerminateJobObject (job, 0);
    exit (0);
  }
  printf ("Child processes were killed after timeout of %u seconds\n",
          timeout);
  TerminateJobObject (job, 1);
  CloseHandle (proc.hProcess);
  exit (1);
}

/* end of timeout_watchdog_w32.c */
