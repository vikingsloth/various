#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char **argv) {
  char *p,
       *iface,
       *stats,
       *arg[16],
       buffer[1024];
  int i;
  FILE *fp;

  setgid(getegid());

  if(!(fp = fopen("/proc/net/dev", "r"))) {
    fprintf(stderr, "Error: can't open file: /proc/net/dev\n");
    exit(-1);
  }

  while(fgets(buffer, sizeof(buffer), fp)) {
    if(!(p = strtok(buffer, ":")))
      continue;
    if(!(iface = strdup(p)))
      continue;
    if(!(p = strtok(NULL, ":")))
      continue;
    if(!(stats = strdup(p)))
      continue;
    if(!(p = strtok(iface, " ")))
      continue;
    if(strcmp(argv[1], p) != 0) 
      continue;

    p = NULL;
    for(i = 0; i < 9; i++) {
      if(!(p = strtok(p ? NULL : stats, " "))) {
        p = NULL;
        break;
      }
      if(!(arg[i] = strdup(p))) {
        p = NULL;
        break;
      }
    }
    if(!p)
      exit(-1);
  
    printf("RX:%s TX:%s\n", arg[0], arg[8]);    
    exit(0);
  }
}

