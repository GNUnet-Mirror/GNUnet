/*
     This file is part of PlibC.
     (C) 2005, 2006, 2007, 2008 Nils Durner (and other contributing authors)

	   This library is free software; you can redistribute it and/or
	   modify it under the terms of the GNU Lesser General Public
	   License as published by the Free Software Foundation; either
	   version 2.1 of the License, or (at your option) any later version.
	
	   This library is distributed in the hope that it will be useful,
	   but WITHOUT ANY WARRANTY; without even the implied warranty of
	   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	   Lesser General Public License for more details.
	
	   You should have received a copy of the GNU Lesser General Public
	   License along with this library; if not, write to the Free Software
	   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/**
 * @file include/plibc.h
 * @brief PlibC header
 * @attention This file is usually not installed under Unix,
 *            so ship it with your application
 * @version $Revision: 1.46 $
 */

#ifndef _PLIBC_H_
#define _PLIBC_H_

#ifndef SIGALRM
#define SIGALRM 14
#endif /*  */

#ifdef __cplusplus
extern "C"
{

#endif                          /*  */

#ifdef Q_OS_WIN32
#define WINDOWS 1
#endif                          /*  */

#define HAVE_PLIBC_FD 0

#ifdef WINDOWS

#if ENABLE_NLS
#include "langinfo.h"
#endif                          /*  */

#include <windows.h>
#include <Ws2tcpip.h>
#include <time.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>

#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN

/* Conflicts with our definitions */
#define __G_WIN32_H__

/* Convert LARGE_INTEGER to double */
#define Li2Double(x) ((double)((x).HighPart) * 4.294967296E9 + \
  (double) ((x).LowPart))
#define socklen_t int
#define ssize_t int
#define off_t int
#define int64_t long long
#define int32_t long
  struct stat64
  {
    _dev_t st_dev;
    _ino_t st_ino;
    _mode_t st_mode;
    short st_nlink;
    short st_uid;
    short st_gid;
    _dev_t st_rdev;
    __int64 st_size;
    __time64_t st_atime;
    __time64_t st_mtime;
    __time64_t st_ctime;
  };

#ifndef pid_t
#define pid_t int
#endif                          /*  */

#ifndef WEXITSTATUS
#define WEXITSTATUS(status) (((status) & 0xff00) >> 8)
#endif                          /*  */

/* Thanks to the Cygwin project */
#define ENOCSI 43               /* No CSI structure available */
#define EL2HLT 44               /* Level 2 halted */
#ifndef  EDEADLK
#define EDEADLK 45              /* Deadlock condition */
#endif                          /*  */
#ifndef  ENOLCK
#define ENOLCK 46               /* No record locks available */
#endif                          /*  */
#define EBADE 50                /* Invalid exchange */
#define EBADR 51                /* Invalid request descriptor */
#define EXFULL 52               /* Exchange full */
#define ENOANO 53               /* No anode */
#define EBADRQC 54              /* Invalid request code */
#define EBADSLT 55              /* Invalid slot */
#ifndef  EDEADLOCK
#define EDEADLOCK EDEADLK       /* File locking deadlock error */
#endif                          /*  */
#define EBFONT 57               /* Bad font file fmt */
#define ENOSTR 60               /* Device not a stream */
#define ENODATA 61              /* No data (for no delay io) */
#define ETIME 62                /* Timer expired */
#define ENOSR 63                /* Out of streams resources */
#define ENONET 64               /* Machine is not on the network */
#define ENOPKG 65               /* Package not installed */
#define EREMOTE 66              /* The object is remote */
#define ENOLINK 67              /* The link has been severed */
#define EADV 68                 /* Advertise error */
#define ESRMNT 69               /* Srmount error */
#define ECOMM 70                /* Communication error on send */
#define EPROTO 71               /* Protocol error */
#define EMULTIHOP 74            /* Multihop attempted */
#define ELBIN 75                /* Inode is remote (not really error) */
#define EDOTDOT 76              /* Cross mount point (not really error) */
#define EBADMSG 77              /* Trying to read unreadable message */
#define ENOTUNIQ 80             /* Given log. name not unique */
#define EBADFD 81               /* f.d. invalid for this operation */
#define EREMCHG 82              /* Remote address changed */
#define ELIBACC 83              /* Can't access a needed shared lib */
#define ELIBBAD 84              /* Accessing a corrupted shared lib */
#define ELIBSCN 85              /* .lib section in a.out corrupted */
#define ELIBMAX 86              /* Attempting to link in too many libs */
#define ELIBEXEC 87             /* Attempting to exec a shared library */
#ifndef  ENOSYS
#define ENOSYS 88               /* Function not implemented */
#endif                          /*  */
#define ENMFILE 89              /* No more files */
#ifndef  ENOTEMPTY
#define ENOTEMPTY 90            /* Directory not empty */
#endif                          /*  */
#ifndef  ENAMETOOLONG
#define ENAMETOOLONG 91         /* File or path name too long */
#endif                          /*  */
#define ELOOP 92                /* Too many symbolic links */
#define EOPNOTSUPP 95           /* Operation not supported on transport endpoint */
#define EPFNOSUPPORT 96         /* Protocol family not supported */
#define ECONNRESET 104          /* Connection reset by peer */
#define ENOBUFS 105             /* No buffer space available */
#define EAFNOSUPPORT 106        /* Address family not supported by protocol family */
#define EPROTOTYPE 107          /* Protocol wrong type for socket */
#define ENOTSOCK 108            /* Socket operation on non-socket */
#define ENOPROTOOPT 109         /* Protocol not available */
#define ESHUTDOWN 110           /* Can't send after socket shutdown */
#define ECONNREFUSED 111        /* Connection refused */
#define EADDRINUSE 112          /* Address already in use */
#define ECONNABORTED 113        /* Connection aborted */
#define ENETUNREACH 114         /* Network is unreachable */
#define ENETDOWN 115            /* Network interface is not configured */
#ifndef  ETIMEDOUT
#define ETIMEDOUT 116           /* Connection timed out */
#endif                          /*  */
#define EHOSTDOWN 117           /* Host is down */
#define EHOSTUNREACH 118        /* Host is unreachable */
#define EINPROGRESS 119         /* Connection already in progress */
#define EALREADY 120            /* Socket already connected */
#define EDESTADDRREQ 121        /* Destination address required */
#define EMSGSIZE 122            /* Message too long */
#define EPROTONOSUPPORT 123     /* Unknown protocol */
#define ESOCKTNOSUPPORT 124     /* Socket type not supported */
#define EADDRNOTAVAIL 125       /* Address not available */
#define ENETRESET 126           /* Connection aborted by network */
#define EISCONN 127             /* Socket is already connected */
#define ENOTCONN 128            /* Socket is not connected */
#define ETOOMANYREFS 129        /* Too many references: cannot splice */
#define EPROCLIM 130            /* Too many processes */
#define EUSERS 131              /* Too many users */
#define EDQUOT 132              /* Disk quota exceeded */
#define ESTALE 133              /* Unknown error */
#ifndef  ENOTSUP
#define ENOTSUP 134             /* Not supported */
#endif                          /*  */
#define ENOMEDIUM 135           /* No medium (in tape drive) */
#define ENOSHARE 136            /* No such host or network path */
#define ECASECLASH 137          /* Filename exists with different case */
#define EWOULDBLOCK EAGAIN      /* Operation would block */
#define EOVERFLOW 139           /* Value too large for defined data type */

#undef HOST_NOT_FOUND
#define HOST_NOT_FOUND 1
#undef TRY_AGAIN
#define TRY_AGAIN 2
#undef NO_RECOVERY
#define NO_RECOVERY 3
#undef NO_ADDRESS
#define NO_ADDRESS 4

#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define MAP_SHARED  0x1
#define MAP_PRIVATE 0x2         /* unsupported */
#define MAP_FIXED   0x10
#define MAP_FAILED  ((void *)-1)
  struct statfs
  {
    long f_type;                /* type of filesystem (see below) */
    long f_bsize;               /* optimal transfer block size */
    long f_blocks;              /* total data blocks in file system */
    long f_bfree;               /* free blocks in fs */
    long f_bavail;              /* free blocks avail to non-superuser */
    long f_files;               /* total file nodes in file system */
    long f_ffree;               /* free file nodes in fs */
    long f_fsid;                /* file system id */
    long f_namelen;             /* maximum length of filenames */
    long f_spare[6];            /* spare for later */
  };
  extern const struct in6_addr in6addr_any;     /* :: */
  extern const struct in6_addr in6addr_loopback;        /* ::1 */

/* Taken from the Wine project <http://www.winehq.org>
    /wine/include/winternl.h */
  enum SYSTEM_INFORMATION_CLASS
  { SystemBasicInformation = 0, Unknown1, SystemPerformanceInformation = 2, SystemTimeOfDayInformation = 3,     /* was SystemTimeInformation */
    Unknown4, SystemProcessInformation =
      5, Unknown6, Unknown7, SystemProcessorPerformanceInformation =
      8, Unknown9, Unknown10, SystemDriverInformation, Unknown12,
    Unknown13, Unknown14, Unknown15, SystemHandleList, Unknown17,
    Unknown18, Unknown19, Unknown20, SystemCacheInformation,
    Unknown22, SystemInterruptInformation =
      23, SystemExceptionInformation =
      33, SystemRegistryQuotaInformation = 37, SystemLookasideInformation = 45
  };
  typedef struct
  {
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER Reserved1[2];
    ULONG Reserved2;
  } SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

#define sleep(secs) (Sleep(secs * 1000))

/*********************** statfs *****************************/
/* fake block size */
#define FAKED_BLOCK_SIZE 512

/* linux-compatible values for fs type */
#define MSDOS_SUPER_MAGIC     0x4d44
#define NTFS_SUPER_MAGIC      0x5346544E

/*********************** End of statfs ***********************/

#define SHUT_RDWR SD_BOTH

/* Operations for flock() */
#define LOCK_SH  1              /* shared lock */
#define LOCK_EX  2              /* exclusive lock */
#define LOCK_NB  4              /* or'd with one of the above to prevent
                                   blocking */
#define LOCK_UN  8              /* remove lock */

/* Not supported under MinGW */
#define S_IRGRP 0
#define S_IWGRP 0
#define S_IROTH 0
#define S_IXGRP 0
#define S_IWOTH 0
#define S_IXOTH 0
#define S_ISUID 0
#define S_ISGID 0
#define S_ISVTX 0
#define S_IRWXG 0
#define S_IRWXO 0

#define SHUT_WR SD_SEND
#define SHUT_RD SD_RECEIVE
#define SHUT_RDWR SD_BOTH

#define SIGKILL 9
#define SIGTERM 15

#define SetErrnoFromWinError(e) _SetErrnoFromWinError(e, __FILE__, __LINE__)
  BOOL _plibc_CreateShortcut (const char *pszSrc, const char *pszDest);
  BOOL _plibc_DereferenceShortcut (char *pszShortcut);
  char *plibc_ChooseDir (char *pszTitle, unsigned long ulFlags);
  char *plibc_ChooseFile (char *pszTitle, unsigned long ulFlags);
  long QueryRegistry (HKEY hMainKey, char *pszKey, char *pszSubKey,
                      char *pszBuffer, long *pdLength);
  BOOL __win_IsHandleMarkedAsBlocking (SOCKET hHandle);
  void __win_SetHandleBlockingMode (SOCKET s, BOOL bBlocking);
  void __win_DiscardHandleBlockingMode (SOCKET s);
  int _win_isSocketValid (int s);
  int plibc_conv_to_win_path (const char *pszUnix, char *pszWindows);
  unsigned plibc_get_handle_count ();
  typedef void (*TPanicProc) (int, char *);
  void plibc_set_panic_proc (TPanicProc proc);
  int flock (int fd, int operation);
  int fsync (int fildes);
  int inet_pton (int af, const char *src, void *dst);
  int inet_pton4 (const char *src, u_char * dst, int pton);

#if USE_IPV6
  int inet_pton6 (const char *src, u_char * dst);

#endif                          /*  */
  int truncate (const char *fname, int distance);
  int statfs (const char *path, struct statfs *buf);
  const char *hstrerror (int err);
  void gettimeofday (struct timeval *tp, void *tzp);
  int mkstemp (char *tmplate);
  char *strptime (const char *buf, const char *format, struct tm *tm);
  char *ctime (const time_t * clock);
  char *ctime_r (const time_t * clock, char *buf);
  const char *inet_ntop (int af, const void *src, char *dst, size_t size);
  int plibc_init (char *pszOrg, char *pszApp);
  void plibc_shutdown ();
  int plibc_initialized ();
  int plibc_conv_to_win_path_ex (const char *pszUnix, char *pszWindows,
                                 int derefLinks);
  void _SetErrnoFromWinError (long lWinError, char *pszCaller, int iLine);
  void SetErrnoFromWinsockError (long lWinError);
  void SetHErrnoFromWinError (long lWinError);
  void SetErrnoFromHRESULT (HRESULT hRes);
  FILE *_win_fopen (const char *filename, const char *mode);
  DIR *_win_opendir (const char *dirname);
  int _win_open (const char *filename, int oflag, ...);

#ifdef ENABLE_NLS
  char *_win_bindtextdomain (const char *domainname, const char *dirname);

#endif                          /*  */
  int _win_chdir (const char *path);
  int _win_close (int fd);
  int _win_creat (const char *path, mode_t mode);
  int _win_fstat (int handle, struct stat *buffer);
  int _win_ftruncate (int fildes, off_t length);
  int _win_kill (pid_t pid, int sig);
  int _win_pipe (int *phandles);
  int _win_rmdir (const char *path);
  int _win_access (const char *path, int mode);
  int _win_chmod (const char *filename, int pmode);
  char *realpath (const char *file_name, char *resolved_name);
  long _win_random (void);
  int _win_remove (const char *path);
  int _win_rename (const char *oldname, const char *newname);
  int _win_stat (const char *path, struct stat *buffer);
  int _win_stat64 (const char *path, struct stat64 *buffer);
  int _win_unlink (const char *filename);
  int _win_write (int fildes, const void *buf, size_t nbyte);
  int _win_read (int fildes, void *buf, size_t nbyte);
  size_t _win_fwrite (const void *buffer, size_t size, size_t count,
                      FILE * stream);
  size_t _win_fread (void *buffer, size_t size, size_t count, FILE * stream);
  int _win_symlink (const char *path1, const char *path2);
  void *_win_mmap (void *start, size_t len, int access, int flags, int fd,
                   unsigned long long offset);
  int _win_munmap (void *start, size_t length);
  int _win_lstat (const char *path, struct stat *buf);
  int _win_lstat64 (const char *path, struct stat64 *buf);
  int _win_readlink (const char *path, char *buf, size_t bufsize);
  int _win_accept (SOCKET s, struct sockaddr *addr, int *addrlen);
  int _win_printf (const char *format, ...);
  int _win_fprintf (FILE * f, const char *format, ...);
  int _win_vprintf (const char *format, va_list ap);
  int _win_vfprintf (FILE * stream, const char *format, va_list arg_ptr);
  int _win_vsprintf (char *dest, const char *format, va_list arg_ptr);
  int _win_vsnprintf (char *str, size_t size, const char *format,
                      va_list arg_ptr);
  int _win_snprintf (char *str, size_t size, const char *format, ...);
  int _win_sprintf (char *dest, const char *format, ...);
  int _win_vsscanf (const char *str, const char *format, va_list arg_ptr);
  int _win_sscanf (const char *str, const char *format, ...);
  int _win_vfscanf (FILE * stream, const char *format, va_list arg_ptr);
  int _win_vscanf (const char *format, va_list arg_ptr);
  int _win_scanf (const char *format, ...);
  int _win_fscanf (FILE * stream, const char *format, ...);
  pid_t _win_waitpid (pid_t pid, int *stat_loc, int options);
  int _win_bind (SOCKET s, const struct sockaddr *name, int namelen);
  int _win_connect (SOCKET s, const struct sockaddr *name, int namelen);
  int _win_getpeername (SOCKET s, struct sockaddr *name, int *namelen);
  int _win_getsockname (SOCKET s, struct sockaddr *name, int *namelen);
  int _win_getsockopt (SOCKET s, int level, int optname, char *optval,
                       int *optlen);
  int _win_listen (SOCKET s, int backlog);
  int _win_recv (SOCKET s, char *buf, int len, int flags);
  int _win_recvfrom (SOCKET s, void *buf, int len, int flags,
                     struct sockaddr *from, int *fromlen);
  int _win_select (int max_fd, fd_set * rfds, fd_set * wfds, fd_set * efds,
                   const struct timeval *tv);
  int _win_send (SOCKET s, const char *buf, int len, int flags);
  int _win_sendto (SOCKET s, const char *buf, int len, int flags,
                   const struct sockaddr *to, int tolen);
  int _win_setsockopt (SOCKET s, int level, int optname, const void *optval,
                       int optlen);
  int _win_shutdown (SOCKET s, int how);
  SOCKET _win_socket (int af, int type, int protocol);
  struct hostent *_win_gethostbyaddr (const char *addr, int len, int type);
  struct hostent *_win_gethostbyname (const char *name);
  struct hostent *gethostbyname2 (const char *name, int af);
  char *_win_strerror (int errnum);
  int IsWinNT ();
  char *index (const char *s, int c);

#if !HAVE_STRNDUP
  char *strndup (const char *s, size_t n);

#endif                          /*  */
#if !HAVE_STRNLEN
  size_t strnlen (const char *str, size_t maxlen);

#endif                          /*  */

#define strcasecmp(a, b) stricmp(a, b)
#define strncasecmp(a, b, c) strnicmp(a, b, c)

#endif                          /* WINDOWS */

#ifndef WINDOWS
#define DIR_SEPARATOR '/'
#define DIR_SEPARATOR_STR "/"
#define PATH_SEPARATOR ';'
#define PATH_SEPARATOR_STR ";"
#define NEWLINE "\n"

#ifdef ENABLE_NLS
#define BINDTEXTDOMAIN(d, n) bindtextdomain(d, n)
#endif                          /*  */
#define CREAT(p, m) creat(p, m)
#undef FOPEN
#define FOPEN(f, m) fopen(f, m)
#define FTRUNCATE(f, l) ftruncate(f, l)
#define OPENDIR(d) opendir(d)
#define OPEN open
#define CHDIR(d) chdir(d)
#define CLOSE(f) close(f)
#define LSEEK(f, o, w) lseek(f, o, w)
#define RMDIR(f) rmdir(f)
#define ACCESS(p, m) access(p, m)
#define CHMOD(f, p) chmod(f, p)
#define FSTAT(h, b) fstat(h, b)
#define PLIBC_KILL(p, s) kill(p, s)
#define PIPE(h) pipe(h)
#define REMOVE(p) remove(p)
#define RENAME(o, n) rename(o, n)
#define STAT(p, b) stat(p, b)
#define STAT64(p, b) stat64(p, b)
#define UNLINK(f) unlink(f)
#define WRITE(f, b, n) write(f, b, n)
#define READ(f, b, n) read(f, b, n)
#define GN_FREAD(b, s, c, f) fread(b, s, c, f)
#define GN_FWRITE(b, s, c, f) fwrite(b, s, c, f)
#define SYMLINK(a, b) symlink(a, b)
#define MMAP(s, l, p, f, d, o) mmap(s, l, p, f, d, o)
#define MUNMAP(s, l) munmap(s, l)
#define STRERROR(i) strerror(i)
#define RANDOM() random()
#define READLINK(p, b, s) readlink(p, b, s)
#define LSTAT(p, b) lstat(p, b)
#define LSTAT64(p, b) lstat64(p, b)
#define PRINTF printf
#define FPRINTF fprintf
#define VPRINTF(f, a) vprintf(f, a)
#define VFPRINTF(s, f, a) vfprintf(s, f, a)
#define VSPRINTF(d, f, a) vsprintf(d, f, a)
#define VSNPRINTF(str, size, fmt, a) vsnprintf(str, size, fmt, a)
#define _REAL_SNPRINTF snprintf
#define SPRINTF sprintf
#define VSSCANF(s, f, a) vsscanf(s, f, a)
#define SSCANF sscanf
#define VFSCANF(s, f, a) vfscanf(s, f, a)
#define VSCANF(f, a) vscanf(f, a)
#define SCANF scanf
#define FSCANF fscanf
#define WAITPID(p, s, o) waitpid(p, s, o)
#define ACCEPT(s, a, l) accept(s, a, l)
#define BIND(s, n, l) bind(s, n, l)
#define CONNECT(s, n, l) connect(s, n, l)
#define GETPEERNAME(s, n, l) getpeername(s, n, l)
#define GETSOCKNAME(s, n, l) getsockname(s, n, l)
#define GETSOCKOPT(s, l, o, v, p) getsockopt(s, l, o, v, p)
#define LISTEN(s, b) listen(s, b)
#define RECV(s, b, l, f) recv(s, b, l, f)
#define RECVFROM(s, b, l, f, r, o) recvfrom(s, b, l, f, r, o)
#define SELECT(n, r, w, e, t) select(n, r, w, e, t)
#define SEND(s, b, l, f) send(s, b, l, f)
#define SENDTO(s, b, l, f, o, n) sendto(s, b, l, f, o, n)
#define SETSOCKOPT(s, l, o, v, n) setsockopt(s, l, o, v, n)
#define SHUTDOWN(s, h) shutdown(s, h)
#define SOCKET(a, t, p) socket(a, t, p)
#define GETHOSTBYADDR(a, l, t) gethostbyname(a, l, t)
#define GETHOSTBYNAME(n) gethostbyname(n)
#else                           /*  */
#define DIR_SEPARATOR '\\'
#define DIR_SEPARATOR_STR "\\"
#define PATH_SEPARATOR ':'
#define PATH_SEPARATOR_STR ":"
#define NEWLINE "\r\n"

#ifdef ENABLE_NLS
#define BINDTEXTDOMAIN(d, n) _win_bindtextdomain(d, n)
#endif                          /*  */
#define CREAT(p, m) _win_creat(p, m)
#define FOPEN(f, m) _win_fopen(f, m)
#define FTRUNCATE(f, l) _win_ftruncate(f, l)
#define OPENDIR(d) _win_opendir(d)
#define OPEN _win_open
#define CHDIR(d) _win_chdir(d)
#define CLOSE(f) _win_close(f)
#define PLIBC_KILL(p, s) _win_kill(p, s)
#define LSEEK(f, o, w) _win_lseek(f, o, w)
#define FSTAT(h, b) _win_fstat(h, b)
#define RMDIR(f) _win_rmdir(f)
#define ACCESS(p, m) _win_access(p, m)
#define CHMOD(f, p) _win_chmod(f, p)
#define PIPE(h) _win_pipe(h)
#define RANDOM() _win_random()
#define REMOVE(p) _win_remove(p)
#define RENAME(o, n) _win_rename(o, n)
#define STAT(p, b) _win_stat(p, b)
#define STAT64(p, b) _win_stat64(p, b)
#define UNLINK(f) _win_unlink(f)
#define WRITE(f, b, n) _win_write(f, b, n)
#define READ(f, b, n) _win_read(f, b, n)
#define GN_FREAD(b, s, c, f) _win_fread(b, s, c, f)
#define GN_FWRITE(b, s, c, f) _win_fwrite(b, s, c, f)
#define SYMLINK(a, b) _win_symlink(a, b)
#define MMAP(s, l, p, f, d, o) _win_mmap(s, l, p, f, d, o)
#define MUNMAP(s, l) _win_munmap(s, l)
#define STRERROR(i) _win_strerror(i)
#define READLINK(p, b, s) _win_readlink(p, b, s)
#define LSTAT(p, b) _win_lstat(p, b)
#define LSTAT64(p, b) _win_lstat64(p, b)
#define PRINTF(f, ...) _win_printf(f , __VA_ARGS__)
#define FPRINTF(fil, fmt, ...) _win_fprintf(fil, fmt, __VA_ARGS__)
#define VPRINTF(f, a) _win_vprintf(f, a)
#define VFPRINTF(s, f, a) _win_vfprintf(s, f, a)
#define VSPRINTF(d, f, a) _win_vsprintf(d, f, a)
#define VSNPRINTF(str, size, fmt, a) _win_vsnprintf(str, size, fmt, a)
#define _REAL_SNPRINTF(str, size, fmt, ...) _win_snprintf(str, size, fmt, __VA_ARGS__)
#define SPRINTF(d, f, ...) _win_sprintf(d, f, __VA_ARGS__)
#define VSSCANF(s, f, a) _win_vsscanf(s, f, a)
#define SSCANF(s, f, ...) _win_sscanf(s, f, __VA_ARGS__)
#define VFSCANF(s, f, a) _win_vfscanf(s, f, a)
#define VSCANF(f, a) _win_vscanf(f, a)
#define SCANF(f, ...) _win_scanf(f, __VA_ARGS__)
#define FSCANF(s, f, ...) _win_fscanf(s, f, __VA_ARGS__)
#define WAITPID(p, s, o) _win_waitpid(p, s, o)
#define ACCEPT(s, a, l) _win_accept(s, a, l)
#define BIND(s, n, l) _win_bind(s, n, l)
#define CONNECT(s, n, l) _win_connect(s, n, l)
#define GETPEERNAME(s, n, l) _win_getpeername(s, n, l)
#define GETSOCKNAME(s, n, l) _win_getsockname(s, n, l)
#define GETSOCKOPT(s, l, o, v, p) _win_getsockopt(s, l, o, v, p)
#define LISTEN(s, b) _win_listen(s, b)
#define RECV(s, b, l, f) _win_recv(s, b, l, f)
#define RECVFROM(s, b, l, f, r, o) _win_recvfrom(s, b, l, f, r, o)
#define SELECT(n, r, w, e, t) _win_select(n, r, w, e, t)
#define SEND(s, b, l, f) _win_send(s, b, l, f)
#define SENDTO(s, b, l, f, o, n) _win_sendto(s, b, l, f, o, n)
#define SETSOCKOPT(s, l, o, v, n) _win_setsockopt(s, l, o, v, n)
#define SHUTDOWN(s, h) _win_shutdown(s, h)
#define SOCKET(a, t, p) _win_socket(a, t, p)
#define GETHOSTBYADDR(a, l, t) _win_gethostbyname(a, l, t)
#define GETHOSTBYNAME(n) _win_gethostbyname(n)
#endif                          /*  */

#ifdef __cplusplus
}
#endif                          /*  */

#endif                          //_PLIBC_H_

/* end of plibc.h */
