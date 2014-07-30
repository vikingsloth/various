/* sloth@htols.net - 01/05/2010
 *
 * Receiver code isn't done but this works just fine:
 * tcpdump -i eth0 -n -s 50 dst port <your port> and 'tcp[13] = 18'
 * 
 * Spoofed TCP SYN scan to offload ip reputation hits from port scanning
 * use your fast server to send the packets and use your cheap DSL/VPS
 * to listen for the SYN/SYNACK.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <signal.h>
#include <time.h>

struct ip_header {
  uint8_t  len:4,
           version:4;
  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t sum;
  uint32_t saddr;
  uint32_t daddr;
} __attribute__((packed));

struct tcp_header {
  uint16_t sport;
  uint16_t dport;
  uint32_t seq;
  uint32_t ack_seq;
  uint8_t  len;
  uint8_t  flags;
  uint16_t win;
  uint16_t sum;
  uint16_t urg;
} __attribute__((packed));

struct tcp_packet {
  struct ip_header iph;
  struct tcp_header tcph;
};

struct Receiver {
  struct in_addr       addr;
  uint16_t             sport;
  int                  sock;
  struct tcp_packet    *tcp_packet;
  struct sockaddr_in   sin;
};

uint32_t tot_count = 0, last_count = 0;
uint8_t  timer = 10;

void usage(char *message) {
  fprintf(stderr, "usage: ./flood_ns [options]\n"
         "  -r <ip>/<bitmask>  * random scan ex: 192.168.1.0/24\n"
         "  -p <port>          * scan port\n"
         "  -l <filename>      * host[:port] list of receivers\n"
         "  -u <number>        * random scan reusable seed\n"
         "  -C <number>        * random scan resume count\n"
         "%s", message ? message : "");
  exit(-1);
}

void fatal(char *reason) {
  fprintf(stderr, "fatal: %s\n", reason);
  exit(-1);
}

void update_count() {
  uint32_t delta;

  delta = tot_count - last_count;
  printf("--------------------------------\n"
         "  Counter:          %u\n"
         "  hosts/second:     %u\n"
         "  kilobits/second:  %u\n",
         tot_count, delta / timer,
         ((sizeof(struct tcp_header) * 8) * (delta / timer)) / 1000);
  last_count = tot_count;
  alarm(timer);
}

struct tcp_packet *alloc_packet() {
  struct tcp_packet *packet;
  struct ip_header  *iph;
  struct tcp_header *tcph;

  if(!(packet = malloc(sizeof(struct tcp_packet))))
    fatal("error: allocating tcp packet");

  iph  = &packet->iph;
  tcph = &packet->tcph;

  iph->len       = 5;
  iph->version   = 4;
  iph->tos       = 0;
  iph->tot_len   = htons(sizeof(struct tcp_packet));
  iph->id        = 0xffff; //1 + (int)(65000.0 * (rand() / (RAND_MAX + 1.0)));;
  iph->frag_off  = 0;
  iph->ttl       = 255;

  iph->protocol  = 6;

  tcph->seq      = random();
  tcph->ack_seq  = random();
  tcph->win      = htons(8192);
  tcph->len      = 5 << 4;
  tcph->flags    = 2;
  return(packet);
}

void init_packet(long source, int sport, long dest, int port,
                 struct tcp_packet *tcp_packet) {
  struct ip_header *iph;
  struct tcp_header *tcph;

  iph  = &tcp_packet->iph;
  tcph = &tcp_packet->tcph;

  iph->saddr  = source;
  iph->daddr  = dest;
  iph->sum    = 0; // csum((unsigned short *)iph, sizeof(struct ip_header));

  tcph->sum   = 0;
  tcph->sport = htons(sport);
  tcph->dport = htons(port);
}

void do_scan(uint16_t dport, struct Receiver *rx_list, uint32_t ip_base, 
             uint32_t seed, char shift) {
  struct tcp_packet *tcp_packet;
  struct ip_header  *iph;
  struct tcp_header *tcph;
  char *pos;
  uint16_t sport;
  uint32_t x, y, i, s, olen, tmp[32];
  register int count = 20 >> 1,sum;
  register unsigned short *p;
  struct in_addr ip;

  /* pre-init packets */
  for(i = 0; rx_list[i].addr.s_addr; i++) {

    tcp_packet        = alloc_packet();

    if(!rx_list[i].sport) 
      rx_list[i].sport = 1024 + (int)(65000.0 * (rand() / (RAND_MAX + 1024.0)));

    sport = rx_list[i].sport;
    init_packet(rx_list[i].addr.s_addr, sport, 0, dport, tcp_packet);

    rx_list[i].tcp_packet          = tcp_packet;

    rx_list[i].sin.sin_family      = AF_INET;
    rx_list[i].sin.sin_addr.s_addr = inet_addr("1.1.1.1");
    rx_list[i].sin.sin_port        = htons(sport);

    if((s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
      fprintf(stderr, "ERROR send_packet() -> socket()\n");
    }
    else if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, &olen, sizeof(olen)) < 0) {
      fprintf(stderr, "ERROR: could not set socket option IP_HDRINCL.\n");
      close(s);
    }

    rx_list[i].sock = s;

  }

  /* initialize random scan parameters */
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

  /* scan */
  signal(SIGALRM, update_count);
  alarm(timer);

  for(i = 0; tot_count < (0xffffffff >> (32 - shift)); tot_count++, i++) {

    if(!rx_list[i].addr.s_addr)
      i = 0;

    iph  = &rx_list[i].tcp_packet->iph;
    tcph = &rx_list[i].tcp_packet->tcph;

    for(y = 0, x = 0; y < shift; y++) {
      tmp[y] = ((tot_count >> y) & 1) << pos[y];
      x += tmp[y];
    }

    iph->daddr = htonl(x + htonl(ip_base));

    count = 20 >> 1;
    tcph->sum = 0;
    p = (uint16_t *)&rx_list[i].tcp_packet->tcph;

    sum = (iph->saddr >> 16) + (iph->saddr & 0xffff) + (iph->daddr >> 16)
          + (iph->daddr & 0xffff) + 1536 + htons(count << 1);

    while(count--) sum += *p++;

    sum = (sum >> 16) + (sum & 0xffff);
    tcph->sum = ~(sum += (sum >> 16));

    if(sendto(rx_list[i].sock, rx_list[i].tcp_packet, sizeof(struct tcp_packet),
       0, (struct sockaddr *)&rx_list[i].sin, sizeof(rx_list[i].sin)) < 1) {
      printf("sendto() failed, backing off\n");
      usleep(50);
    }
       

  }

}

long resolve(char *host) {
  struct in_addr ip;
  struct hostent *he;

  if((ip.s_addr = inet_addr(host)) == -1) {
    if(!(he = gethostbyname(host)))
      return(-1);
    else
      memcpy(&ip.s_addr, he->h_addr, 4);
  }
  return(ip.s_addr);
}

struct Receiver *read_rxs(char *filename) {
  FILE *fp;
  uint32_t len = 0, count = 0, i;
  struct Receiver *rx_list;
  struct in_addr ip;
  char buffer[256], *p;

  if(!(fp = fopen(filename, "r"))) {
    fprintf(stderr, "Error: can't open file: %s\n", filename);
    exit(-1);
  }

  len = 256 * sizeof(struct Receiver);

  if(!(rx_list = malloc(len))) {
    fprintf(stderr, "Error: malloc\n");
    exit(-1);
  }

  while(fgets(buffer, sizeof(buffer), fp)) {

    if (count >= (len / sizeof(struct Receiver)) - 2) {
      if (!(rx_list = realloc(rx_list, len + 
                              (256 * sizeof(struct Receiver))))) {
        fprintf(stderr, "Error: realloc\n");
        exit(-1);
      }

      len += 256 * sizeof(struct Receiver);
    }

    if(buffer[strlen(buffer) - 1] == '\n')
      buffer[strlen(buffer) - 1] = 0;

    if(!(p = strchr(buffer, ':'))) 
      rx_list[count].sport = 0;
    else {
      *p = 0;
      p++;
      rx_list[count].sport = atoi(p);
//printf("%d %d\n", rx_list[count].sport, atoi(p));
    }

    if((rx_list[count].addr.s_addr = resolve(buffer)) == -1)
      continue;

    printf("%s:%u\n", inet_ntoa(rx_list[count].addr), rx_list[count].sport);
    count++;

  }

  printf("*** Loaded %u Receivers ***\n", count);

  if(!count) {
    fprintf(stderr, "Error: 0 Receivers Found\n");
    exit(-1);
  }

  return(rx_list);
}

int main(int argc, char *argv[]) {
  struct Receiver *rx_list;
  struct in_addr ip_base;
  uint16_t shift = 0;
  uint32_t c, i, dport, stime, rseed, dtime;
  char rxlist_file[255], *p;

  printf("###### scansyn_tx.c - sloth@ww88.org ######\n");

  if(argc == 1)
    usage(NULL);

  ip_base.s_addr = 0;
  rxlist_file[0] = 0;

  while((c = getopt(argc, argv, "l:p:r:u:C:")) != -1) {

    switch(c) {

      case 'l':

        strncpy(rxlist_file, optarg, sizeof(rxlist_file) - 1);
        break;

      case 'p':

        dport = atoi(optarg);
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

        printf("random scanning %s/%d\n", inet_ntoa(ip_base), 32 - shift);
        break;

      case 'u':

        rseed = atoi(optarg);
        printf("resumable seed: %d\n", rseed);
        break;

      case 'C':

        tot_count = atol(optarg);
        printf("resumable count: %d\n", tot_count);
        break;

      default:

        usage(NULL);
        exit(-1);

    }

  }

  if(!dport)
    usage("-p is required\n");

  if(!ip_base.s_addr && !shift)
    usage("-r is required\n");

  if(!rxlist_file[0])
    usage("-l is required\n");

  printf("hosts to scan: %d\n", 0xffffffff >> (32 - shift));

  rx_list = read_rxs(rxlist_file);

  stime = time(0);
  srand(getpid() * getuid() + time(0));

  do_scan(dport, rx_list, ip_base.s_addr, rseed, shift);

  if(!(dtime = time(0) - stime))
    dtime = 1;

  printf("-------- COMPLETED SCAN ---------\n"
         "  Hosts Scanned:     %u\n"
         "  Total Seconds:     %u\n"
         "  hosts/second:      %u\n"
         "  kilobits/second:   %u\n",
         tot_count, 
         dtime, 
         tot_count / dtime, 
         ((tot_count * sizeof(struct tcp_packet) * 8) / 1000) / dtime);
}

