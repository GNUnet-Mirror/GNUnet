/*
     W32 version of 'cat' program
     Copyright (C) 2012 LRN

     cat is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     cat is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with cat; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

#include <stdio.h>
#include <windows.h>
#include <stdint.h>
#include <signal.h>

DWORD WINAPI
parent_control_thread (LPVOID lpParameter)
{
  HANDLE h = (HANDLE) lpParameter;
  while (TRUE)
  {
    DWORD dw;
    BOOL b;
    unsigned char c;
    b = ReadFile (h, &c, 1, &dw, NULL);
    if (!b)
    {
      ExitProcess (0);
    }
    raise ((int) c);
  }
}

void
install_parent_control_handler ()
{
  const char *env_buf;
  char *env_buf_end;
  uint64_t pipe_fd;
  HANDLE pipe_handle;

  env_buf = getenv ("GNUNET_OS_CONTROL_PIPE");
  if ( (NULL == env_buf) || (strlen (env_buf) <= 0) )
    return;
  errno = 0;
  pipe_fd = strtoull (env_buf, &env_buf_end, 16);
  if ((0 != errno) || (env_buf == env_buf_end))
    return;
  /* Gcc will issue a warning here. What to do with it? */
  pipe_handle = (HANDLE) (uintptr_t) pipe_fd;
  CreateThread (NULL, 0, parent_control_thread, (LPVOID) pipe_handle, 0, NULL);
}

int
main (int argc, char **argv)
{
  HANDLE stdi, stdo;
  BOOL b;
  wchar_t *commandlinew, **argvw;
  int argcw;
  int i;

  stdo = GetStdHandle (STD_OUTPUT_HANDLE);
  if (stdo == INVALID_HANDLE_VALUE || stdo == NULL)
    return 1;

  commandlinew = GetCommandLineW ();
  argvw = CommandLineToArgvW (commandlinew, &argcw);
  if (argvw == NULL)
    return 1;

  install_parent_control_handler ();

  for (i = 1; i < argcw || argcw == 1; i++)
  {
    DWORD r, w;
    int is_dash = wcscmp (NULL == argvw[i] ? L"-" : argvw[i], L"-") == 0;
    if (argcw == 1 || is_dash)
    {
      stdi = GetStdHandle (STD_INPUT_HANDLE);
      if (stdi == INVALID_HANDLE_VALUE)
      {
        fprintf (stderr, "cat: Failed to obtain stdin handle.\n");
        return 4;
      }
      if (stdi == NULL)
      {
        fprintf (stderr, "cat: Have no stdin.\n");
        return 5;
      }
    }
    else
    {
      stdi = CreateFileW (argvw[i], GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
      if (stdi == INVALID_HANDLE_VALUE)
      {
        wchar_t *msgbuf;
        DWORD le = GetLastError ();
        if (0 < FormatMessageW (FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, 0, le, 0, (wchar_t *) &msgbuf, 0, NULL))
        {
          fprintf (stderr, "cat: Failed to open file `%S'. Error %lu.\n", argvw[i], le);
          return 3;
        }
        fprintf (stderr, "cat: Failed to open file `%S'. Error %lu: %S\n", argvw[i], le, msgbuf);
        if (msgbuf != NULL)
          LocalFree (msgbuf);
        return 2;
      }
    }
    do
    {
      unsigned char c;
      b = ReadFile (stdi, &c, 1, &r, NULL);
      if (b && r > 0)
      {
        b = WriteFile (stdo, &c, 1, &w, NULL);
        if (b == 0)
        {
          wchar_t *msgbuf;
          DWORD le = GetLastError ();
          if (0 < FormatMessageW (FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, 0, le, 0, (wchar_t *) &msgbuf, 0, NULL))
          {
            fprintf (stderr, "cat: Failed to write into stdout. Error %lu.\n", le);
            return 3;
          }
          fprintf (stderr, "cat: Failed to write into stdout. Error %lu: %S\n", le, msgbuf);
          if (msgbuf != NULL)
            LocalFree (msgbuf);
          return 6;
        }
      }
    } while (b && r > 0);
    if (argcw == 1)
      break;
    if (!is_dash)
      CloseHandle (stdi);
  }
  LocalFree (argvw);
  return 0;
}
