/* bannergit.c - sloth@htols.net 2009
 * 
 * quickly hacked up banner scanner to follow up with the SYN scanner
 */

#include <stdio.h>
#include <string.h> 
#include <unistd.h> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <sys/types.h> 
#include <netdb.h> 
#include <sys/time.h> 
#include <signal.h> 
#include <time.h> 
#include <stdarg.h> 
#include <sys/stat.h> 
#include <regex.h>
#include <stdlib.h>

struct Expect {
  char *needle,
       *logmsg;
};

struct Connection {
  int    s;
  short  flags;
  time_t stime;
};

char *logfile, log_dir[128];
int maxchildren = 200;

struct Expect expect[] = {
  { "linksys", "linksys"       },
  { "vpn",     "vpn"           },
  { "setup",   "generic setup" },
  { NULL,      NULL            }
};
 
void usage(char *message) {
  printf("Usage: ./bannergit -s <start ip> -e <end ip> [options]\n"
         "  -s <ip>            * start ip\n"
         "  -e <ip>            * end ip\n"
         "  -r <ip>/<bitmask>  * random scan ex: 192.168.1.0/24\n"
         "  -u <number>        * random scan reusable seed\n"
         "  -C <number>        * random scan resume count\n"
         "  -i                 * stdin scan\n"
         "  -p <port>          * port\n"
         "  -b <directory>     * save banners to directory\n"
         "  -l <file>          * file to log to\n"
         "  -t <seconds>       * connect timeout [5]\n"
         "  -d <seconds>       * login timeout [20]\n"
         "  -c <number>        * max children [200]\n"
         "%s", message ? message : "");
  exit(-1); 
}

void logit(char *filename, char *fmt, ...) { 
  FILE *file; 
  char buffer[2048]; 
  va_list ap; 

  va_start(ap, fmt); 
  vsnprintf(buffer, sizeof(buffer) - 1, fmt, ap); 

  if((file = fopen(filename, "a")) == NULL) { 
    fprintf(stderr, "Could not open %s for writing. Disabling writing\n", 
            filename);
    exit(-1);
  }

  fprintf(file, "%s", buffer);       
  fclose(file); 
  va_end(ap); 
} 

void killchild(int signum) {
  exit(-1);
}

int make_connection(struct in_addr ip, int port) {
  int s; 
  struct sockaddr_in sin; 
 
  sin.sin_addr=ip; 
  sin.sin_family=AF_INET; 
  sin.sin_port=htons(port); 
 
  if((s=socket(AF_INET, SOCK_STREAM, 0))<=0) { 
    printf("socket() error\n"); 
    return(-1); 
  } 
 
#ifdef DEBUG 
  printf("Connecting to %s:%d\n", inet_ntoa(sin.sin_addr), port); 
#endif 

  if(connect(s, (struct sockaddr *)&sin, sizeof(sin))<0) { 

#ifdef DEBUG 
    printf("Could not connect to %s:%d\n", inet_ntoa(sin.sin_addr), port); 
#endif 

    close(s); 
    return(-1); 
  } 
 
  return(s);  
}

void data_wait(int s) {
  fd_set fdrs;

  FD_ZERO(&fdrs);
  FD_SET(s, &fdrs);

  if(select(s+1, &fdrs, NULL, NULL, NULL) == -1)
    exit(-1);  
}

char *data_read(int s, size_t size) {
  char *buffer;
  size_t left, len;
  int r;

  if(size) {
    left = size;
    len  = size;
  }
    
  if(!(buffer = malloc(len)))
    return(NULL);

  buffer[0] = 0;
  data_wait(s);

  
  while((r = read(s, buffer+(len - left), left - 1)) > 0) {

    left -= r;

    if(!size && left < 128) {
      if(!(buffer = realloc(buffer, len + 8192)))
        return(NULL);

      len  += 8192;
      left += 8192;
    }

    data_wait(s);

  }

  buffer[len - left] = 0;

}

int regex_wrapper(char *expect, char *buffer) {
  regex_t re;

  if (regcomp(&re, expect, REG_EXTENDED|REG_NOSUB) != 0)
    return(-1);

  if(regexec(&re, buffer, 0, NULL, 0) != 0) {
    regfree(&re);
    return(0);
  } 

  return(1);
}

int my_strcasestr(char *haystack, char *needle) {
  char *tmphaystack,
       *tmpneedle;
  int i;

  if((tmphaystack = (char *)calloc(1, strlen(haystack))) == NULL) 
    return(-1);

  if((tmpneedle = (char *)calloc(1, strlen(needle))) == NULL) {
    free(tmphaystack);
    return(-1);
  }

  for(i = 0; i < strlen(haystack); i++) 
    tmphaystack[i] = toupper(haystack[i]);

  for(i = 0; i < strlen(needle); i++)
    tmpneedle[i] = toupper(needle[i]);

  if(strstr(tmphaystack, tmpneedle)) {
    free(tmphaystack);
    free(tmpneedle);
    return(0);
  }
}

void log_event(char *fmt, ...) {
  FILE *fp;
  char buffer[2048];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, ap);
  va_end(ap);

  printf("%s", buffer);

  if(!logfile)
    return;

  if((fp = fopen(logfile, "a")) == NULL) {
    fprintf(stderr, "couldn't open log file [%s]\n", logfile);
    exit(-1);
  }

  fprintf(fp, "%s", buffer);
  fclose(fp);
}

void log_banner(struct in_addr ip, char *banner) {
  char filename[256];

  snprintf(filename, sizeof(filename) - 1, "%s/%s", log_dir, inet_ntoa(ip));

  logit(filename, banner);
}

void get_banner(int s, struct in_addr ip, int ltout) {
  char *buffer;
  regex_t re;
  int i;

  signal(SIGALRM, killchild);
  alarm(ltout);

  if(!(buffer = data_read(s, 0)))
    return;
  
  if(log_dir[0])
    log_banner(ip, buffer);
  // logit("debug.log", "%s [%d] %s\n", inet_ntoa(ip), strlen(buffer), buffer);

  for(i = 0; expect[i].needle; i++) {

    if(my_strcasestr(buffer, expect[i].needle)) {
      log_event("%s %s\n", inet_ntoa(ip), expect[i].logmsg);
      break;
    }

  }

  free(buffer);
}

void openport(struct in_addr ip, int port, int tout, int ltout) {
  int s;

  signal(SIGALRM, killchild); 
  alarm(tout); 

  if((s = make_connection(ip, port)) < 0) { 
    alarm(0); 
    signal(SIGALRM, SIG_DFL); 
    return;  
  } 

  alarm(0);
  signal(SIGALRM, SIG_DFL);

  get_banner(s, ip, ltout);
}

void rscan(unsigned int ip_base, char shift, unsigned int count, int seed,
                                 int port, int tout, int ltout) {
  int children = 0, y;
  unsigned int i, x, tmp[32];
  unsigned char *pos;
  struct in_addr sip;

  if(seed)
    srand(seed);
  else {
    seed = 1;
    printf("resume seed: %d\n", seed);
    srand(seed);
  }

  if(!(pos = malloc(shift))) {
    fprintf(stderr, "malloc()\n");
    exit(-1);
  }

  memset(pos, 0, shift);
  memset(&tmp, 0, shift * 4);

  for(i = 0; i < shift;) {
    x = (int)((float)shift*rand()/(RAND_MAX+1.0));

    if(tmp[x] || x == i)
      continue;

    pos[i] = x;
    tmp[x] = x+1;
    i++;
  }

  y = 1;
  for(; count < (0xffffffff >> (32 - shift)); count++) {

    if(y > 253) {
      printf("  Current count: %d [%s]\n", count, inet_ntoa(sip));
      y = 0;
    }

    y++;

    for(i = 0, x = 0; i < shift; i++) {
      tmp[i] = ((count >> i) & 1) << pos[i];
      x += tmp[i];
    }

    sip.s_addr = htonl(x + htonl(ip_base));
// printf("%d %s\n", x, inet_ntoa(sip));

    if(children >= maxchildren) {
      wait(NULL);
      children--;
    }

    switch(fork()) {
      case 0:
        openport(sip, port, tout, ltout);
        exit(0);

      case -1:
        fprintf(stderr, "fork()\n");
        exit(-1);

      default:
        children++;
        break;
    }

  }

  while(children--)
    wait(NULL);


}

void stdin_scan(int port, int tout, int ltout) {
  int i, children = 0, test = 0;
  struct in_addr sip;
  char input[256], token[4][20], *p, string_login[256], string_en[256];

  while(fgets(input, sizeof(input), stdin) != NULL) {

    if((i = strlen(input)) < 7)
      continue;

    input[strlen(input) - 1] = 0;

    p = NULL;
    test = 0;

    for(i = 0; i < 3; i++) {
      if(!(p = strtok(p ? NULL : input, ":")))
        break;

      snprintf(token[i], sizeof(token[i]) - 1, "%s", p);
    }

    if(i == 3) 
      test = 1;

    if(!inet_aton(input, &sip)) {
      fprintf(stderr, "error: ip %s invalid\n", input);
      continue;
    }

    if(children >= maxchildren) {
      wait(NULL);
      children--;
    }

    switch(fork()) {
      case 0:
        /* holy shit what a mess this hack is */
        openport(sip, port, tout, ltout);
        exit(0);

      case -1:
        fprintf(stderr, "fork()\n");
        exit(-1);

      default:
        children++;
        break;
    }

  }

  while(children--)
    wait(NULL);

}

void portscan(struct in_addr start, struct in_addr end, int port, 
              int tout, int ltout) {
  int children = 0;
  struct in_addr curr;
  int i;

  curr.s_addr = start.s_addr;

  if(htonl(curr.s_addr) > htonl(end.s_addr)) {
    fprintf(stderr, "Start ip must be less than end ip");
    exit(-1);
  }

  i = 1;
  while(htonl(curr.s_addr) < htonl(end.s_addr)) {

    if(i > 255) {
      printf("  Current IP: %s\n", inet_ntoa(curr));
      i = 0;
    }

    i++;

    if(children > maxchildren) {
      wait(NULL);
      children--;
    }

// printf("%X trans:%s\n", curr.s_addr, inet_ntoa(trans));

    switch(fork()) {
      case 0:
        openport(curr, port, tout, ltout);
        exit(0);

      case -1:
        fprintf(stderr, "fork() error!\n");
        exit(-1);

      default:
        children++;
        break;
    }

    curr.s_addr = htonl(htonl(curr.s_addr) + 1);
  }

  while(children--) 
    wait(NULL);

  printf("finished...\n");
}

int main(int argc, char *argv[]) {
  struct in_addr start, end, ip_base;
  int c, ltout = 20, tout = 5, port = 80, stime = 0, std_input = 0, 
      do_rscan = 0, rseed = 0;
  unsigned short shift;
  unsigned long count = 0;
  char *p;

  printf("wrt_login.c - sloth@ww88.org sup GNAA\n\n"
         "#### START CONFIG ####\n");

  log_dir[0]   = 0;
  start.s_addr = 0;
  end.s_addr   = 0;

  while((c = getopt(argc, argv, "b:is:e:t:d:l:c:p:r:u:C:")) != -1) {

    switch(c) {

      case 'b':

        strncpy(log_dir, optarg, sizeof(log_dir));
        printf("banner log dir: %s\n", log_dir);
        break;

      case 'i':

        std_input = 1;
        break;

      case 's':

        if((start.s_addr = inet_addr(optarg)) == -1) {
          printf("invalid start ip [%s]\n", optarg);
          exit(-1);
        }

        printf("startip: %s\n", inet_ntoa(start));
        break;

      case 'e':

        if((end.s_addr = inet_addr(optarg)) == -1) {
          printf("invalid end ip [%s]\n", optarg);
          exit(-1);
        }

        printf("endip: %s\n", inet_ntoa(end));
        break;

      case 'l':
 
        logfile = optarg;
        printf("logfile: %s\n", logfile);
        break;

      case 'd':

        ltout = atoi(optarg);
        printf("login timeout: %d\n", ltout);
        break;

      case 't':

        tout = atoi(optarg);
        printf("connect timeout: %d\n", tout);
        break;

      case 'c':

        maxchildren = atoi(optarg);
        printf("max children: %d\n", maxchildren);
        break;

      case 'r':

        if(!(p = strchr(optarg, '/')))
          usage("error: invalid range ex: 192.168.1.0/24\n");

        p[0] = 0;
        if(!inet_aton(optarg, &ip_base))
          usage("error: invalid random base address\n");

        p++;
        shift = 32 - atoi(p);
        if(shift > 32)
          usage("error: invalid range ex: 192.168.1.0/24\n");

        printf("random scanning %s/%d\n", inet_ntoa(ip_base), shift);
        do_rscan = 1;
        break;

      case 'u':

        rseed = atoi(optarg);
        printf("resumable seed: %d\n", rseed);
        break;

      case 'C':

        count = atol(optarg);
        printf("resumable count: %lu\n", count);
        break;

      default:

        usage(NULL);
        exit(-1);

    }

  }

  if((!start.s_addr || !end.s_addr) && !std_input && !do_rscan) {
    fprintf(stderr, "you must have a start and end ip\n");
    usage(NULL);
  }

  if(!std_input && !do_rscan) 
    printf("hosts to scan: %d\n", htonl(end.s_addr) - htonl(start.s_addr));
  else if(do_rscan)
    printf("hosts to scan: %d\n", 0xffffffff >> (32 - shift));

  printf("#### END CONFIG ####\n\n");

  stime = time(0);

  if(std_input) {
    stdin_scan(port, tout, ltout);
    exit(0);
  }

  if(do_rscan) {
    rscan(ip_base.s_addr, shift, count, rseed, port, tout, ltout);
    printf("%lu hosts scanned in %lu seconds\n",
      (0xffffffff >> (32 - shift)) - count, time(0) - stime);
    exit(0);
  } 

  portscan(start, end, port, tout, ltout);
  printf("%u hosts scanned in %lu seconds\n", 
         htonl(end.s_addr) - htonl(start.s_addr), time(0) - stime);
}
