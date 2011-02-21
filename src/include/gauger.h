#ifndef __GAUGER_H__
#define __GAUGER_H__

#ifndef WINDOWS

#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>

#define GAUGER(counter, value) {char __gauger_s[64];pid_t __gauger_p;if(!(__gauger_p=fork())){if(!fork()){sprintf(__gauger_s,"%llu", (unsigned long long) value);execlp("gauger-cli.py","gauger-cli.py",counter, __gauger_s,(char*)NULL);_exit(1);}else{_exit(0);}}else{waitpid(__gauger_p,NULL,0);}}

#else

#define GAUGER(counter, value) {}

#endif

#endif
