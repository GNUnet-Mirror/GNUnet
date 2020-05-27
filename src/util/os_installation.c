/*
     This file is part of GNUnet.
     Copyright (C) 2006-2018 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file src/util/os_installation.c
 * @brief get paths used by the program
 * @author Milan
 * @author Christian Fuchs
 * @author Christian Grothoff
 * @author Matthias Wachs
 * @author Heikki Lindholm
 * @author LRN
 */
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <unistr.h> /* for u16_to_u8 */

#include "platform.h"
#include "gnunet_util_lib.h"
#if DARWIN
#include <mach-o/ldsyms.h>
#include <mach-o/dyld.h>
#endif


#define LOG(kind, ...) \
  GNUNET_log_from (kind, "util-os-installation", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind, syscall, filename)       \
  GNUNET_log_from_strerror_file (kind,                   \
                                 "util-os-installation", \
                                 syscall,                \
                                 filename)


/**
 * Default project data used for installation path detection
 * for GNUnet (core).
 */
static const struct GNUNET_OS_ProjectData default_pd = {
  .libname = "libgnunetutil",
  .project_dirname = "gnunet",
  .binary_name = "gnunet-arm",
  .version = PACKAGE_VERSION " " VCS_VERSION,
  .env_varname = "GNUNET_PREFIX",
  .base_config_varname = "GNUNET_BASE_CONFIG",
  .bug_email = "gnunet-developers@gnu.org",
  .homepage = "http://www.gnu.org/s/gnunet/",
  .config_file = "gnunet.conf",
  .user_config_file = "~/.config/gnunet.conf",
  .is_gnu = 1,
  .gettext_domain = PACKAGE,
  .gettext_path = NULL,
  .agpl_url = GNUNET_AGPL_URL,
};

/**
 * Which project data do we currently use for installation
 * path detection? Never NULL.
 */
static const struct GNUNET_OS_ProjectData *current_pd = &default_pd;

/**
 * Wether or not gettext has been initialized for the library.
 * Note that the gettext initialization done within
 * GNUNET_PROGRAM_run2 is for the specific application.
 */
static int gettextinit = 0;

/**
 * Return default project data used by 'libgnunetutil' for GNUnet.
 */
const struct GNUNET_OS_ProjectData *
GNUNET_OS_project_data_default (void)
{
  return &default_pd;
}


/**
 * @return current project data.
 */
const struct GNUNET_OS_ProjectData *
GNUNET_OS_project_data_get ()
{
  if (0 == gettextinit)
  {
    char *path = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_LOCALEDIR);
    if (NULL != path)
      bindtextdomain (PACKAGE, path);
    GNUNET_free (path);
    gettextinit = 1;
  }
  return current_pd;
}


/**
 * Setup OS subsystem with project data.
 *
 * @param pd project data used to determine paths
 */
void
GNUNET_OS_init (const struct GNUNET_OS_ProjectData *pd)
{
  if (0 == gettextinit)
  {
    char *path = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_LOCALEDIR);
    if (NULL != path)
      bindtextdomain (PACKAGE, path);
    GNUNET_free (path);
    gettextinit = 1;
  }
  GNUNET_assert (NULL != pd);
  current_pd = pd;
}


#ifdef __linux__
/**
 * Try to determine path by reading /proc/PID/exe
 *
 * @return NULL on error
 */
static char *
get_path_from_proc_maps ()
{
  char fn[64];
  char line[1024];
  char dir[1024];
  FILE *f;
  char *lgu;

  GNUNET_snprintf (fn, sizeof(fn), "/proc/%u/maps", getpid ());
  if (NULL == (f = fopen (fn, "r")))
    return NULL;
  while (NULL != fgets (line, sizeof(line), f))
  {
    if ((1 == sscanf (line,
                      "%*x-%*x %*c%*c%*c%*c %*x %*2x:%*2x %*u%*[ ]%1023s",
                      dir)) &&
        (NULL != (lgu = strstr (dir, current_pd->libname))))
    {
      lgu[0] = '\0';
      fclose (f);
      return GNUNET_strdup (dir);
    }
  }
  fclose (f);
  return NULL;
}


/**
 * Try to determine path by reading /proc/PID/exe
 *
 * @return NULL on error
 */
static char *
get_path_from_proc_exe ()
{
  char fn[64];
  char lnk[1024];
  ssize_t size;
  char *lep;

  GNUNET_snprintf (fn, sizeof(fn), "/proc/%u/exe", getpid ());
  size = readlink (fn, lnk, sizeof(lnk) - 1);
  if (size <= 0)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "readlink", fn);
    return NULL;
  }
  GNUNET_assert (((size_t) size) < sizeof(lnk));
  lnk[size] = '\0';
  while ((lnk[size] != '/') && (size > 0))
    size--;
  GNUNET_asprintf (&lep, "/%s/libexec/", current_pd->project_dirname);
  /* test for being in lib/gnunet/libexec/ or lib/MULTIARCH/gnunet/libexec */
  if ((((size_t) size) > strlen (lep)) &&
      (0 == strcmp (lep, &lnk[size - strlen (lep)])))
    size -= strlen (lep) - 1;
  GNUNET_free (lep);
  if ((size < 4) || (lnk[size - 4] != '/'))
  {
    /* not installed in "/bin/" -- binary path probably useless */
    return NULL;
  }
  lnk[size] = '\0';
  return GNUNET_strdup (lnk);
}


#endif


#if DARWIN
/**
 * Signature of the '_NSGetExecutablePath" function.
 *
 * @param buf where to write the path
 * @param number of bytes available in @a buf
 * @return 0 on success, otherwise desired number of bytes is stored in 'bufsize'
 */
typedef int (*MyNSGetExecutablePathProto) (char *buf, size_t *bufsize);


/**
 * Try to obtain the path of our executable using '_NSGetExecutablePath'.
 *
 * @return NULL on error
 */
static char *
get_path_from_NSGetExecutablePath ()
{
  static char zero = '\0';
  char *path;
  size_t len;
  MyNSGetExecutablePathProto func;

  path = NULL;
  if (NULL ==
      (func = (MyNSGetExecutablePathProto) dlsym (RTLD_DEFAULT,
                                                  "_NSGetExecutablePath")))
    return NULL;
  path = &zero;
  len = 0;
  /* get the path len, including the trailing \0 */
  (void) func (path, &len);
  if (0 == len)
    return NULL;
  path = GNUNET_malloc (len);
  if (0 != func (path, &len))
  {
    GNUNET_free (path);
    return NULL;
  }
  len = strlen (path);
  while ((path[len] != '/') && (len > 0))
    len--;
  path[len] = '\0';
  return path;
}


/**
 * Try to obtain the path of our executable using '_dyld_image' API.
 *
 * @return NULL on error
 */
static char *
get_path_from_dyld_image ()
{
  const char *path;
  char *p;
  char *s;
  unsigned int i;
  int c;

  c = _dyld_image_count ();
  for (i = 0; i < c; i++)
  {
    if (((const void *) _dyld_get_image_header (i)) !=
        ((const void *) &_mh_dylib_header))
      continue;
    path = _dyld_get_image_name (i);
    if ((NULL == path) || (0 == strlen (path)))
      continue;
    p = GNUNET_strdup (path);
    s = p + strlen (p);
    while ((s > p) && ('/' != *s))
      s--;
    s++;
    *s = '\0';
    return p;
  }
  return NULL;
}


#endif


/**
 * Return the actual path to a file found in the current
 * PATH environment variable.
 *
 * @param binary the name of the file to find
 * @return path to binary, NULL if not found
 */
static char *
get_path_from_PATH (const char *binary)
{
  char *path;
  char *pos;
  char *end;
  char *buf;
  const char *p;

  if (NULL == (p = getenv ("PATH")))
    return NULL;

  path = GNUNET_strdup (p);  /* because we write on it */

  buf = GNUNET_malloc (strlen (path) + strlen (binary) + 1 + 1);
  pos = path;
  while (NULL != (end = strchr (pos, PATH_SEPARATOR)))
  {
    *end = '\0';
    sprintf (buf, "%s/%s", pos, binary);
    if (GNUNET_DISK_file_test (buf) == GNUNET_YES)
    {
      pos = GNUNET_strdup (pos);
      GNUNET_free (buf);
      GNUNET_free (path);
      return pos;
    }
    pos = end + 1;
  }
  sprintf (buf, "%s/%s", pos, binary);
  if (GNUNET_YES == GNUNET_DISK_file_test (buf))
  {
    pos = GNUNET_strdup (pos);
    GNUNET_free (buf);
    GNUNET_free (path);
    return pos;
  }
  GNUNET_free (buf);
  GNUNET_free (path);
  return NULL;
}


/**
 * Try to obtain the installation path using the "GNUNET_PREFIX" environment
 * variable.
 *
 * @return NULL on error (environment variable not set)
 */
static char *
get_path_from_GNUNET_PREFIX ()
{
  const char *p;

  if ((NULL != current_pd->env_varname) &&
      (NULL != (p = getenv (current_pd->env_varname))))
    return GNUNET_strdup (p);
  if ((NULL != current_pd->env_varname_alt) &&
      (NULL != (p = getenv (current_pd->env_varname_alt))))
    return GNUNET_strdup (p);
  return NULL;
}


/**
 * @brief get the path to GNUnet bin/ or lib/, prefering the lib/ path
 * @author Milan
 *
 * @return a pointer to the executable path, or NULL on error
 */
static char *
os_get_gnunet_path ()
{
  char *ret;

  if (NULL != (ret = get_path_from_GNUNET_PREFIX ()))
    return ret;
#ifdef __linux__
  if (NULL != (ret = get_path_from_proc_maps ()))
    return ret;
  /* try path *first*, before /proc/exe, as /proc/exe can be wrong */
  if ((NULL != current_pd->binary_name) &&
      (NULL != (ret = get_path_from_PATH (current_pd->binary_name))))
    return ret;
  if (NULL != (ret = get_path_from_proc_exe ()))
    return ret;
#endif
#if DARWIN
  if (NULL != (ret = get_path_from_dyld_image ()))
    return ret;
  if (NULL != (ret = get_path_from_NSGetExecutablePath ()))
    return ret;
#endif
  if ((NULL != current_pd->binary_name) &&
      (NULL != (ret = get_path_from_PATH (current_pd->binary_name))))
    return ret;
  /* other attempts here */
  LOG (GNUNET_ERROR_TYPE_ERROR,
       _ (
         "Could not determine installation path for %s.  Set `%s' environment variable.\n"),
       current_pd->project_dirname,
       current_pd->env_varname);
  return NULL;
}


/**
 * @brief get the path to current app's bin/
 * @return a pointer to the executable path, or NULL on error
 */
static char *
os_get_exec_path ()
{
  char *ret = NULL;

#ifdef __linux__
  if (NULL != (ret = get_path_from_proc_exe ()))
    return ret;
#endif
#if DARWIN
  if (NULL != (ret = get_path_from_NSGetExecutablePath ()))
    return ret;
#endif
  /* other attempts here */
  return ret;
}


/**
 * @brief get the path to a specific GNUnet installation directory or,
 * with #GNUNET_OS_IPK_SELF_PREFIX, the current running apps installation directory
 * @return a pointer to the dir path (to be freed by the caller)
 */
char *
GNUNET_OS_installation_get_path (enum GNUNET_OS_InstallationPathKind dirkind)
{
  size_t n;
  char *dirname;
  char *execpath = NULL;
  char *tmp;
  char *multiarch;
  char *libdir;
  int isbasedir;

  /* if wanted, try to get the current app's bin/ */
  if (dirkind == GNUNET_OS_IPK_SELF_PREFIX)
    execpath = os_get_exec_path ();

  /* try to get GNUnet's bin/ or lib/, or if previous was unsuccessful some
   * guess for the current app */
  if (NULL == execpath)
    execpath = os_get_gnunet_path ();

  if (NULL == execpath)
    return NULL;

  n = strlen (execpath);
  if (0 == n)
  {
    /* should never happen, but better safe than sorry */
    GNUNET_free (execpath);
    return NULL;
  }
  /* remove filename itself */
  while ((n > 1) && (DIR_SEPARATOR == execpath[n - 1]))
    execpath[--n] = '\0';

  isbasedir = 1;
  if ((n > 6) && ((0 == strcasecmp (&execpath[n - 6], "/lib32")) ||
                  (0 == strcasecmp (&execpath[n - 6], "/lib64"))))
  {
    if ((GNUNET_OS_IPK_LIBDIR != dirkind) &&
        (GNUNET_OS_IPK_LIBEXECDIR != dirkind))
    {
      /* strip '/lib32' or '/lib64' */
      execpath[n - 6] = '\0';
      n -= 6;
    }
    else
      isbasedir = 0;
  }
  else if ((n > 4) && ((0 == strcasecmp (&execpath[n - 4], "/bin")) ||
                       (0 == strcasecmp (&execpath[n - 4], "/lib"))))
  {
    /* strip '/bin' or '/lib' */
    execpath[n - 4] = '\0';
    n -= 4;
  }
  multiarch = NULL;
  if (NULL != (libdir = strstr (execpath, "/lib/")))
  {
    /* test for multi-arch path of the form "PREFIX/lib/MULTIARCH/";
       here we need to re-add 'multiarch' to lib and libexec paths later! */
    multiarch = &libdir[5];
    if (NULL == strchr (multiarch, '/'))
      libdir[0] =
        '\0';   /* Debian multiarch format, cut of from 'execpath' but preserve in multicarch */
    else
      multiarch =
        NULL;   /* maybe not, multiarch still has a '/', which is not OK */
  }
  /* in case this was a directory named foo-bin, remove "foo-" */
  while ((n > 1) && (execpath[n - 1] == DIR_SEPARATOR))
    execpath[--n] = '\0';
  switch (dirkind)
  {
  case GNUNET_OS_IPK_PREFIX:
  case GNUNET_OS_IPK_SELF_PREFIX:
    dirname = GNUNET_strdup (DIR_SEPARATOR_STR);
    break;

  case GNUNET_OS_IPK_BINDIR:
    dirname = GNUNET_strdup (DIR_SEPARATOR_STR "bin" DIR_SEPARATOR_STR);
    break;

  case GNUNET_OS_IPK_LIBDIR:
    if (isbasedir)
    {
      GNUNET_asprintf (&tmp,
                       "%s%s%s%s%s%s%s",
                       execpath,
                       DIR_SEPARATOR_STR "lib",
                       (NULL != multiarch) ? DIR_SEPARATOR_STR : "",
                       (NULL != multiarch) ? multiarch : "",
                       DIR_SEPARATOR_STR,
                       current_pd->project_dirname,
                       DIR_SEPARATOR_STR);
      if (GNUNET_YES == GNUNET_DISK_directory_test (tmp, GNUNET_YES))
      {
        GNUNET_free (execpath);
        return tmp;
      }
      GNUNET_free (tmp);
      tmp = NULL;
      dirname = NULL;
      if (4 == sizeof(void *))
      {
        GNUNET_asprintf (&dirname,
                         DIR_SEPARATOR_STR "lib32" DIR_SEPARATOR_STR
                         "%s" DIR_SEPARATOR_STR,
                         current_pd->project_dirname);
        GNUNET_asprintf (&tmp, "%s%s", execpath, dirname);
      }
      if (8 == sizeof(void *))
      {
        GNUNET_asprintf (&dirname,
                         DIR_SEPARATOR_STR "lib64" DIR_SEPARATOR_STR
                         "%s" DIR_SEPARATOR_STR,
                         current_pd->project_dirname);
        GNUNET_asprintf (&tmp, "%s%s", execpath, dirname);
      }

      if ((NULL != tmp) &&
          (GNUNET_YES == GNUNET_DISK_directory_test (tmp, GNUNET_YES)))
      {
        GNUNET_free (execpath);
        GNUNET_free_non_null (dirname);
        return tmp;
      }
      GNUNET_free (tmp);
      GNUNET_free_non_null (dirname);
    }
    GNUNET_asprintf (&dirname,
                     DIR_SEPARATOR_STR "%s" DIR_SEPARATOR_STR,
                     current_pd->project_dirname);
    break;

  case GNUNET_OS_IPK_DATADIR:
    GNUNET_asprintf (&dirname,
                     DIR_SEPARATOR_STR "share" DIR_SEPARATOR_STR
                     "%s" DIR_SEPARATOR_STR,
                     current_pd->project_dirname);
    break;

  case GNUNET_OS_IPK_LOCALEDIR:
    dirname = GNUNET_strdup (DIR_SEPARATOR_STR "share" DIR_SEPARATOR_STR
                             "locale" DIR_SEPARATOR_STR);
    break;

  case GNUNET_OS_IPK_ICONDIR:
    dirname = GNUNET_strdup (DIR_SEPARATOR_STR "share" DIR_SEPARATOR_STR
                             "icons" DIR_SEPARATOR_STR);
    break;

  case GNUNET_OS_IPK_DOCDIR:
    GNUNET_asprintf (&dirname,
                     DIR_SEPARATOR_STR "share" DIR_SEPARATOR_STR
                     "doc" DIR_SEPARATOR_STR
                     "%s" DIR_SEPARATOR_STR,
                     current_pd->project_dirname);
    break;

  case GNUNET_OS_IPK_LIBEXECDIR:
    if (isbasedir)
    {
      GNUNET_asprintf (&dirname,
                       DIR_SEPARATOR_STR "%s" DIR_SEPARATOR_STR
                       "libexec" DIR_SEPARATOR_STR,
                       current_pd->project_dirname);
      GNUNET_asprintf (&tmp,
                       "%s%s%s%s",
                       execpath,
                       DIR_SEPARATOR_STR "lib" DIR_SEPARATOR_STR,
                       (NULL != multiarch) ? multiarch : "",
                       dirname);
      GNUNET_free (dirname);
      if (GNUNET_YES == GNUNET_DISK_directory_test (tmp, GNUNET_YES))
      {
        GNUNET_free (execpath);
        return tmp;
      }
      GNUNET_free (tmp);
      tmp = NULL;
      dirname = NULL;
      if (4 == sizeof(void *))
      {
        GNUNET_asprintf (&dirname,
                         DIR_SEPARATOR_STR "lib32" DIR_SEPARATOR_STR
                         "%s" DIR_SEPARATOR_STR
                         "libexec" DIR_SEPARATOR_STR,
                         current_pd->project_dirname);
        GNUNET_asprintf (&tmp, "%s%s", execpath, dirname);
      }
      if (8 == sizeof(void *))
      {
        GNUNET_asprintf (&dirname,
                         DIR_SEPARATOR_STR "lib64" DIR_SEPARATOR_STR
                         "%s" DIR_SEPARATOR_STR
                         "libexec" DIR_SEPARATOR_STR,
                         current_pd->project_dirname);
        GNUNET_asprintf (&tmp, "%s%s", execpath, dirname);
      }
      if ((NULL != tmp) &&
          (GNUNET_YES == GNUNET_DISK_directory_test (tmp, GNUNET_YES)))
      {
        GNUNET_free (execpath);
        GNUNET_free_non_null (dirname);
        return tmp;
      }
      GNUNET_free (tmp);
      GNUNET_free_non_null (dirname);
    }
    GNUNET_asprintf (&dirname,
                     DIR_SEPARATOR_STR "%s" DIR_SEPARATOR_STR
                     "libexec" DIR_SEPARATOR_STR,
                     current_pd->project_dirname);
    break;

  default:
    GNUNET_free (execpath);
    return NULL;
  }
  GNUNET_asprintf (&tmp, "%s%s", execpath, dirname);
  GNUNET_free (dirname);
  GNUNET_free (execpath);
  return tmp;
}


/**
 * Given the name of a gnunet-helper, gnunet-service or gnunet-daemon
 * binary, try to prefix it with the libexec/-directory to get the
 * full path.
 *
 * @param progname name of the binary
 * @return full path to the binary, if possible, otherwise copy of 'progname'
 */
char *
GNUNET_OS_get_libexec_binary_path (const char *progname)
{
  static char *cache;
  char *libexecdir;
  char *binary;

  if ((DIR_SEPARATOR == progname[0]) ||
      (GNUNET_YES ==
       GNUNET_STRINGS_path_is_absolute (progname, GNUNET_NO, NULL, NULL)))
    return GNUNET_strdup (progname);
  if (NULL != cache)
    libexecdir = cache;
  else
    libexecdir = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_LIBEXECDIR);
  if (NULL == libexecdir)
    return GNUNET_strdup (progname);
  GNUNET_asprintf (&binary, "%s%s", libexecdir, progname);
  cache = libexecdir;
  return binary;
}


/**
 * Given the name of a helper, service or daemon binary construct the full
 * path to the binary using the SUID_BINARY_PATH in the PATHS section of the
 * configuration. If that option is not present, fall back to
 * GNUNET_OS_get_libexec_binary_path. If @a progname is an absolute path, a
 * copy of this path is returned.
 *
 * @param cfg configuration to inspect
 * @param progname name of the binary
 * @return full path to the binary, if possible, a copy of @a progname
 *         otherwise
 */
char *
GNUNET_OS_get_suid_binary_path (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                const char *progname)
{
  static char *cache;
  char *binary = NULL;
  char *path = NULL;
  size_t path_len;

  if (GNUNET_YES ==
      GNUNET_STRINGS_path_is_absolute (progname, GNUNET_NO, NULL, NULL))
  {
    return GNUNET_strdup (progname);
  }
  if (NULL != cache)
    path = cache;
  else
    GNUNET_CONFIGURATION_get_value_string (cfg,
                                           "PATHS",
                                           "SUID_BINARY_PATH",
                                           &path);
  if ((NULL == path) || (0 == strlen (path)))
    return GNUNET_OS_get_libexec_binary_path (progname);
  path_len = strlen (path);
  GNUNET_asprintf (&binary,
                   "%s%s%s",
                   path,
                   (path[path_len - 1] == DIR_SEPARATOR) ? ""
                   : DIR_SEPARATOR_STR,
                   progname);
  cache = path;
  return binary;
}


/**
 * Check whether an executable exists and possibly if the suid bit is
 * set on the file.  Attempts to find the file using the current PATH
 * environment variable as a search path.
 *
 * @param binary the name of the file to check.
 *        W32: must not have an .exe suffix.
 * @param check_suid input true if the binary should be checked for SUID (*nix)
 *        W32: checks if the program has sufficient privileges by executing this
 *             binary with the -d flag. -d omits a programs main loop and only
 *             executes all privileged operations in an binary.
 * @param params parameters used for w32 privilege checking (can be NULL for != w32 )
 * @return #GNUNET_YES if the file is SUID (*nix) or can be executed with current privileges (W32),
 *         #GNUNET_NO if not SUID (but binary exists),
 *         #GNUNET_SYSERR on error (no such binary or not executable)
 */
int
GNUNET_OS_check_helper_binary (const char *binary,
                               int check_suid,
                               const char *params)
{
  struct stat statbuf;
  char *p;
  char *pf;

  if ((GNUNET_YES ==
       GNUNET_STRINGS_path_is_absolute (binary, GNUNET_NO, NULL, NULL)) ||
      (0 == strncmp (binary, "./", 2)))
  {
    p = GNUNET_strdup (binary);
  }
  else
  {
    p = get_path_from_PATH (binary);
    if (NULL != p)
    {
      GNUNET_asprintf (&pf, "%s/%s", p, binary);
      GNUNET_free (p);
      p = pf;
    }
  }

  if (NULL == p)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         _ ("Could not find binary `%s' in PATH!\n"),
         binary);
    return GNUNET_SYSERR;
  }
  if (0 != access (p, X_OK))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "access", p);
    GNUNET_free (p);
    return GNUNET_SYSERR;
  }

  if (0 == getuid ())
  {
    /* as we run as root, we don't insist on SUID */
    GNUNET_free (p);
    return GNUNET_YES;
  }

  if (0 != stat (p, &statbuf))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "stat", p);
    GNUNET_free (p);
    return GNUNET_SYSERR;
  }
  if (check_suid)
  {
    (void) params;
    if ((0 != (statbuf.st_mode & S_ISUID)) && (0 == statbuf.st_uid))
    {
      GNUNET_free (p);
      return GNUNET_YES;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Binary `%s' exists, but is not SUID\n"),
                p);
    /* binary exists, but not SUID */
  }
  GNUNET_free (p);
  return GNUNET_NO;
}


/* end of os_installation.c */
