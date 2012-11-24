/** ---------------------------------------------------------------------------
 * This software is in the public domain, furnished "as is", without technical
 * support, and with no warranty, express or implied, as to its usefulness for
 * any purpose.
 *
 * gauger.h
 * Interface for C programs to log remotely to a gauger server
 *
 * Author: Bartlomiej Polot
 * -------------------------------------------------------------------------*/
#ifndef __GAUGER_H__
#define __GAUGER_H__

#ifndef WINDOWS

#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>

#define GAUGER(category, counter, value, unit)\
{\
    char* __gauger_v[10];\
    char __gauger_s[32];\
    pid_t __gauger_p;\
    if(!(__gauger_p=fork())){\
        close (1);	     \
        close (2);	     \
        if(!fork()){\
            sprintf(__gauger_s,"%Lf", (long double) (value));\
            __gauger_v[0] = "gauger";\
            __gauger_v[1] = "-n";\
            __gauger_v[2] = (char*) (counter);	\
            __gauger_v[3] = "-d";\
            __gauger_v[4] = __gauger_s;\
            __gauger_v[5] = "-u";\
            __gauger_v[6] = (char*) (unit);	\
            __gauger_v[7] = "-c";\
            __gauger_v[8] = (char*) (category);	\
            __gauger_v[9] = (char*) NULL;\
            execvp("gauger",__gauger_v);\
            _exit(1);\
        }else{\
            _exit(0);\
        }\
    }else{\
        waitpid(__gauger_p,NULL,0);\
    }\
}

#define GAUGER_ID(category, counter, value, unit, id)\
{\
    char* __gauger_v[12];\
    char __gauger_s[32];\
    pid_t __gauger_p;\
    if(!(__gauger_p=fork())){\
        close (1);	     \
        close (2);	     \
        if(!fork()){\
            sprintf(__gauger_s,"%Lf", (long double) (value));\
            __gauger_v[0] = "gauger";\
            __gauger_v[1] = "-n";\
            __gauger_v[2] = (char*) (counter);	\
            __gauger_v[3] = "-d";\
            __gauger_v[4] = __gauger_s;\
            __gauger_v[5] = "-u";\
            __gauger_v[6] = (char*) (unit);	\
            __gauger_v[7] = "-i";\
            __gauger_v[8] = id;\
            __gauger_v[9] = "-c";\
            __gauger_v[10] = (char *) (category);	\
            __gauger_v[11] = (char *) NULL;\
            execvp("gauger",__gauger_v);\
            _exit(1);\
        }else{\
            _exit(0);\
        }\
    }else{\
        waitpid(__gauger_p, NULL, 0);\
    }\
}

#else /* WINDOWS */

#include <stdlib.h>
#include <stdio.h>
#include <windef.h>

#define GAUGER(category, counter, value, unit)\
{\
    char __gauger_commandline[MAX_PATH];\
    \
    snprintf (__gauger_commandline, MAX_PATH, "gauger.py -n \"%s\" -d \"%Lf\" -u \"%s\" -c \"%s\"",\
	      (counter), (long double) (value), (unit), (category));	\
    __gauger_commandline[MAX_PATH - 1] = '\0';\
    system (__gauger_commandline);\
}

#define GAUGER_ID(category, counter, value, unit, id)\
{\
    char __gauger_commandline[MAX_PATH];\
    \
    snprintf (__gauger_commandline, MAX_PATH, "gauger.py -n \"%s\" -d \"%Lf\" -u \"%s\" -i \"%s\" -c \"%s\"",\
	      (counter), (long double) (value), (unit), (id), (category)); \
    __gauger_commandline[MAX_PATH - 1] = '\0';\
    system (__gauger_commandline);\
}

#endif // WINDOWS

#endif
