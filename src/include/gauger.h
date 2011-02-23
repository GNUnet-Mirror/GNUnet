#ifndef __GAUGER_H__
#define __GAUGER_H__

#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>

#define GAUGER(counter, value, unit) {char* __gauger_v[8];char __gauger_s[32];pid_t __gauger_p; if(!(__gauger_p=fork())){if(!fork()){sprintf(__gauger_s,"%llu", (unsigned long long) (value));__gauger_v[0] = "gauger-cli.py";__gauger_v[1] = "-n";__gauger_v[2] = counter;__gauger_v[3] = "-d";__gauger_v[4] = __gauger_s;__gauger_v[5] = "-u";__gauger_v[6] = unit;__gauger_v[7] = (char *)NULL;execvp("gauger-cli.py",__gauger_v);perror("gauger");_exit(1);}else{_exit(0);}}else{waitpid(__gauger_p,NULL,0);}}

#define GAUGER_ID(counter, value, unit, id) {char* __gauger_v[10];char __gauger_s[32];pid_t __gauger_p; if(!(__gauger_p=fork())){if(!fork()){sprintf(__gauger_s,"%llu", (unsigned long long) (value));__gauger_v[0] = "gauger-cli.py";__gauger_v[1] = "-n";__gauger_v[2] = counter;__gauger_v[3] = "-d";__gauger_v[4] = __gauger_s;__gauger_v[5] = "-u";__gauger_v[6] = unit;__gauger_v[7] = "-i";__gauger_v[8] = id;__gauger_v[9] = (char *)NULL;execvp("gauger-cli.py",__gauger_v);perror("gauger");_exit(1);}else{_exit(0);}}else{waitpid(__gauger_p,NULL,0);}}

#endif
