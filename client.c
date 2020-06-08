#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ip/resolv.h"
#include "speck.h"

#include <string.h>
#include <stdbool.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define SEND_INTERVAL		15 * CLOCK_SECOND
#define BROADCAST_PORT 10000


static struct uip_udp_conn *client_conn; 
static struct uip_udp_conn *broadcast_conn;
int idx;

#define DATA_LEN 10

char buf[DATA_LEN+10];
char encrypted_data[DATA_LEN+33];        

unsigned long long key[2] = {0x0706050403020100, 0x0f0e0d0c0b0a0908};
int mode = 1;

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler()
{
  char *str;

  if(uip_newdata()) {
    idx++;
    str = uip_appdata;
    str[uip_datalen()] = '\0';

    strcpy(encrypted_data, str);

    decrypt(encrypted_data, buf, key, mode);
    printf("%d: received a broadcast of %d bytes: %c\n", idx, strlen(buf), buf[0]);
    // printf("Response from the server: '%s'\n", str);
  }
}
/*---------------------------------------------------------------------------*/

static void
send_handler(void)
{
    // strcpy(buf, "Hello\0");
  // static int seq_id=0;
  // buf[0] = '0'+seq_id;
  // seq_id++;

  encrypt(buf, encrypted_data, key, mode);

  printf("Client sending to: ");
  PRINT6ADDR(&client_conn->ripaddr);
  printf(" (msg: %s)\n", encrypted_data);


#if SEND_TOO_LARGE_PACKET_TO_TEST_FRAGMENTATION
  uip_udp_packet_send(client_conn, buf, UIP_APPDATA_SIZE);
#else /* SEND_TOO_LARGE_PACKET_TO_TEST_FRAGMENTATION */
  uip_udp_packet_send(client_conn, encrypted_data, strlen(encrypted_data));
#endif /* SEND_TOO_LARGE_PACKET_TO_TEST_FRAGMENTATION */
}


/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer et;
  uip_ipaddr_t ipaddr;
  char ch;

  PROCESS_BEGIN();  
  
  ch = '0'+((int)(linkaddr_node_addr.u8[7])%10);
  
  PRINTF("%c UDP client process started\n", ch);

  /* new connection with remote host */
  
  broadcast_conn = udp_new(NULL, UIP_HTONS(BROADCAST_PORT), NULL);
  udp_bind(broadcast_conn, UIP_HTONS(BROADCAST_PORT));
  
  uip_ip6addr(&ipaddr, 0xfe80, 0, 0, 0, 0xc30c, 0, 0, 0x1);
  
  client_conn = udp_new(&ipaddr, UIP_HTONS(3000), NULL);
  udp_bind(client_conn, UIP_HTONS(3001));

  
  idx=0;
  ch = '0'+((int)(linkaddr_node_addr.u8[7])%10);
  for(int i1=0; i1<DATA_LEN; i1++)
    buf[i1]=ch;
  buf[DATA_LEN-1]='\0';


          // PRINTF("Created a connection with the server ");
          // PRINT6ADDR(&(client_conn->ripaddr));
          // PRINTF(" local/remote port %u/%u\n",
          // UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));

  send_handler();

  etimer_set(&et, SEND_INTERVAL);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  
  send_handler();
  
  // etimer_set(&et, SEND_INTERVAL);
  while(1) {
    PROCESS_YIELD();
    // if(etimer_expired(&et)) {
    //   timeout_handler();
    //   etimer_restart(&et);
    // } else 
    if(ev == tcpip_event) {
      tcpip_handler(&idx);
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
