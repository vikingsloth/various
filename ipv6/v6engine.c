/* sloth@htols - 06/08/2011
 *
 * IPv6 packet generator engine library
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

char tmpaddr[INET6_ADDRSTRLEN];
#define NTOP(a) inet_ntop(AF_INET6,&a,tmpaddr,INET6_ADDRSTRLEN)

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
} __attribute__((packed));;

struct ip6_header {
  union {
    struct ip6_hdrctl {
      uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
                                  20 bits flow-ID */
      uint16_t ip6_un1_plen;   /* payload length */
      uint8_t  ip6_un1_nxt;    /* next header */
      uint8_t  ip6_un1_hlim;   /* hop limit */
    } ip6_un1;
    uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
  } ip6_ctlun;
  struct in6_addr ip6_src;      /* source address */
  struct in6_addr ip6_dst;      /* destination address */
};

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

struct udp_header {
} __attribute__((packed));

struct icmp6_header {
  uint8_t  type;
  uint8_t  code;
  uint16_t checksum;
} __attribute__((packed));

enum ICMPType {
  ICMP_NULL,
  ICMP_UNREACH,
  ICMP_TOOBIG,
  ICMP_TIMEEXCEEDED,
  ICMP_ERROR,
  ICMP_ECHO = 128,
  ICMP_ECHOREPLY = 129
};

void *create_packet(uint8_t type, uint16_t data_len, size_t *plen,
                    uint32_t source, uint32_t dest,
                    struct in6_addr *ip6_src, uint16_t sport, 
                    struct in6_addr *ip6_dst, uint16_t dport) {
  void *packet;
  struct ip6_header   *ip6h  = NULL;
  struct ip_header    *iph   = NULL;
  struct tcp_header   *tcph  = NULL;
  struct udp_header   *udph  = NULL;
  struct icmp6_header *icmph = NULL;
  size_t clen = 0;
  int i;

  if (!sport)
    sport = 1024 + (int)(65000.0 * (rand() / (RAND_MAX + 1024.0)));

  if (!dport)
    dport = 1 + (int)(65000.0 * (rand() / (RAND_MAX + 1.0)));

  if (dest && !source)
    source = (random() << 16) + (random() & 0xffff);

  *plen = sizeof(struct ip6_header) + data_len;

  // 4 to 6 tunnel header
  if (dest)
    *plen += sizeof(struct ip_header);

  switch(type) {
    case IPPROTO_TCP:
      *plen += sizeof(struct tcp_header);
      break;
    case IPPROTO_UDP:
      *plen += sizeof(struct udp_header);
      break;
    case IPPROTO_ICMPV6:
      *plen += sizeof(struct icmp6_header);
      break;
    default:
      fatal("invalid type");
  }
  
  if(!(packet = malloc(*plen)))
    fatal("error: allocating tcp packet");

  // IPv6 over IPv6 tunnel defaults
  if (dest) {
    iph = (struct ip_header *)packet;
    clen = sizeof(struct ip_header);
    iph->len       = 5;
    iph->version   = 4;
    iph->tos       = 0;
    iph->tot_len   = htons(*plen);
    iph->id        = 1 + (int)(65000.0 * (rand() / (RAND_MAX + 1.0)));;
    iph->frag_off  = 0;
    iph->ttl       = 255;
    iph->protocol  = IPPROTO_IPV6;
    iph->sum       = 0;
    iph->saddr     = source;
    iph->daddr     = dest;
  }

  ip6h = (struct ip6_header *)(packet + clen);
  clen += sizeof(struct ip6_header);

  memcpy(&ip6h->ip6_src, ip6_src, sizeof(struct in6_addr));
  memcpy(&ip6h->ip6_dst, ip6_dst, sizeof(struct in6_addr));

  ip6h->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);
  ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt  = type;
  ip6h->ip6_ctlun.ip6_un1.ip6_un1_hlim = 64;

  switch(type) {

    case IPPROTO_TCP:
      ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen =
        htons(sizeof(struct tcp_header) + data_len);

      tcph = (struct tcp_header *)(packet + clen);
      clen += sizeof(struct tcp_header);

      tcph->seq     = random();
      tcph->ack_seq = 0;
      tcph->len     = 5 << 4;
      tcph->flags   = 2;
      tcph->win     = htons(8192);
      tcph->urg     = 0;
      tcph->sum     = 0;
      tcph->sport = htons(sport);
      tcph->dport = htons(dport);
      break;

    // XXX - setup UDP defaults
    case IPPROTO_UDP:
      ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen =
        htons(sizeof(struct udp_header) + data_len);

      udph = (struct udp_header *)(packet + clen);
      clen += sizeof(struct udp_header);
      break;

    case IPPROTO_ICMPV6:
      ip6h->ip6_ctlun.ip6_un1.ip6_un1_plen =
        htons(sizeof(struct icmp6_header) + data_len);

      icmph = (struct icmp6_header *)(packet + clen);
      icmph->type = ICMP_ECHO;
      icmph->code = 0;
      icmph->checksum = 0;
      clen += sizeof(struct icmp6_header);
      break;
  }

  return(packet);
}

void tcp_generator(int s, void *packet, size_t plen, struct ip_header *iph,
                   struct ip6_header *ip6h, struct tcp_header *tcph,
                   struct sockaddr *sa, size_t sa_len) {
  register int count = 20 >> 1,sum,psum;
  register unsigned short *p;
  int i;

  // Pre-calcualte static data checksum for efficiency
  psum = 1536 + htons(20);

  count = 8; // 128/16, number of 16bit chunks to sum
  p = (uint16_t *)&ip6h->ip6_dst;
  while(count--) psum += *p++;

  count = 8; // 20/2 16bit chunks of tcp packet size minus sport/dport
  p = (uint16_t *)&tcph->seq;
  while(count--) psum += *p++;

  for (;;) {
    // Pre-calculated checksum data
    sum = psum;
 
    // Checksum source address
    count = 8; // 128/16, number of 16bit chunks to sum
    p = (uint16_t *)&ip6h->ip6_src;
    while(count--) sum += *p++;

    sum += tcph->sport;
    sum += tcph->dport;

    sum = (sum >> 16) + (sum & 0xffff);
    tcph->sum = ~(sum += (sum >> 16));

    sendto(s, packet, plen, 0, sa, sa_len);
    // XXX make this configurable
    sleep(1);
  }
}

void icmp6_generator(int s, void *packet, size_t plen, struct ip_header *iph,
                     struct ip6_header *ip6h, struct icmp6_header *icmph,
                     void *data, size_t data_len,
                     struct sockaddr *sa, size_t sa_len) {
  register int count = 20 >> 1,sum,psum;
  register unsigned short *p;
  int i;
  uint16_t *id;
  uint16_t *seq;

  id = (uint16_t *)(data);
  *id = 1 + (int)(65000.0 * (rand() / (RAND_MAX + 1.0)));
  data += sizeof(*id);
  seq = (uint16_t *)(data);
  data += sizeof(*seq);
  // XXX randomize this and make the length configurable
  memset(data, 0, 56);

  // Pre-calcualte static data checksum for efficiency
  psum = htons(IPPROTO_ICMPV6);
  psum += htons(sizeof(struct icmp6_header) + data_len);

  count = 8; // 128/16, number of 16bit chunks to sum
  p = (uint16_t *)&ip6h->ip6_dst;
  while(count--) psum += *p++;

  psum += *(uint16_t *)&icmph->type;
  psum += *id;
  // XXX if we randomize data later, add to checksum here

  for (;;) {
    // Pre-calculated checksum data
    sum = psum;

    // Checksum source address
    count = 8; // 128/16, number of 16bit chunks to sum
    p = (uint16_t *)&ip6h->ip6_src;
    while(count--) sum += *p++;

    *seq=htons(ntohs(*seq) + 1);
    sum += *seq;

    sum = (sum >> 16) + (sum & 0xffff);
    icmph->checksum = ~(sum += (sum >> 16)); 

    sendto(s, packet, plen, 0, sa, sa_len);
    sleep(1);
  }
}

void generator(uint8_t type, uint32_t source, uint32_t dest,
               struct in6_addr *ip6_src, uint16_t sport,
               struct in6_addr *ip6_dst, uint16_t dport) {
  struct sockaddr_in6  sin6;
  struct sockaddr_in   sin;
  struct sockaddr      *sa;
  struct ip_header     *iph   = NULL;
  struct ip6_header    *ip6h  = NULL;
  struct tcp_header    *tcph  = NULL;
  struct udp_header    *udph  = NULL;
  struct icmp6_header  *icmph = NULL;
  void *packet;
  void *data;
  size_t sa_len;
  size_t data_len = 0;
  size_t plen = 0;
  size_t clen = 0;
  int s;
  int olen;

  if (type == IPPROTO_ICMPV6) {
    data_len = 60;
  }

  packet = create_packet(type, data_len, &plen, source, dest, ip6_src, sport,
                         ip6_dst, dport);

  // IPv6 over IPv4
  if (dest) {
    iph = (struct ip_header *)packet;
    clen = sizeof(struct ip_header);

    sin.sin_family      = AF_INET;
    sin.sin_port        = dport;
    sin.sin_addr.s_addr = dest;

    sa = (struct sockaddr *)&sin;
    sa_len = sizeof(struct sockaddr_in);

    if((s = socket(AF_INET, SOCK_RAW, IPPROTO_IPV6)) < 0) {
      fprintf(stderr, "ERROR send_packet() -> socket()\n");
    }
    else if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, &olen, sizeof(olen)) < 0) {
      fprintf(stderr, "ERROR: could not set socket option IP_HDRINCL.\n");
      close(s);
      exit(-1);
    }
  // IPv6 native
  } else {
    sin6.sin6_family   = AF_INET6;
    // Must be set to 0 or sendto() will fail with EINVAL
    sin6.sin6_port     = 0;
    sin6.sin6_scope_id = 0;
    sin6.sin6_flowinfo = 0;
    memcpy(&sin6.sin6_addr, ip6_dst, sizeof(struct in6_addr));

    sa = (struct sockaddr *)&sin6;
    sa_len = sizeof(struct sockaddr_in6);

    if((s = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
      fprintf(stderr, "ERROR send_packet() -> socket()\n");
      exit(-1);
    }
  }

  ip6h = (struct ip6_header *)(packet + clen);
  clen += sizeof(struct ip6_header);

  switch (type) {
    case IPPROTO_TCP:
      tcph = (struct tcp_header *)(packet + clen);
      tcp_blaster(s, packet, plen, iph, ip6h, tcph, sa, sa_len);
      break;
    case IPPROTO_ICMPV6:
      icmph = (struct icmp6_header *)(packet + clen);
      clen += sizeof(struct icmp6_header);
      data = packet + clen;
      icmp6_blaster(s, packet, plen, iph, ip6h, icmph, data, data_len, sa,
                    sa_len);
      break;
    default:
      fprintf(stderr, "Error: unsupported packet type\n");
      exit(-1);
  }

}
