
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "speck.h"

#include <string.h>

#define DEBUG DEBUG_PRINT

#include "net/ip/uip-debug.h"

#define SEND_INTERVAL		15 * CLOCK_SECOND
#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define BROADCAST_PORT 10000

#define DATA_LEN 10

char buf[DATA_LEN+10];
char encrypted_data[DATA_LEN+33];        

unsigned long long key[2] = {0x0706050403020100, 0x0f0e0d0c0b0a0908};
int mode = 1;

static struct uip_udp_conn *server_conn;
static struct uip_udp_conn *broadcast_conn;

PROCESS(udp_server_process, "UDP server process");
AUTOSTART_PROCESSES(&udp_server_process);

static void send_broadcast(char *buf, int size)
{
        uip_create_linklocal_allnodes_mcast(&broadcast_conn->ripaddr);
        uip_udp_packet_send(broadcast_conn, buf, size);
        uip_create_unspecified(&broadcast_conn->ripaddr);
        // printf("Successfully sent bombs!!\n");
}

/*---------------------------------------------------------------------------*/


static void
tcpip_handler(void)
{
  char *str;
  if(uip_newdata()) {
    str = uip_appdata;
    str[uip_datalen()] = '\0';
    
    printf("**Server Receive event**\n");
    strcpy(encrypted_data, str);

    decrypt(encrypted_data, buf, key, mode);
    printf("Server received a MESSAGE of %d bytes: %c\n", strlen(buf), buf[0]);
    
    encrypt(buf, encrypted_data, key, mode);
    send_broadcast(encrypted_data, strlen(encrypted_data));
    // uip_udp_packet_send(server_conn, buf, strlen(buf));
  }
}
/*---------------------------------------------------------------------------*/

PROCESS_THREAD(udp_server_process, ev, data)
{
  // static struct etimer et;

  PROCESS_BEGIN();
  PRINTF("UDP server started\n");

  server_conn = udp_new(NULL, UIP_HTONS(3001), NULL);
  udp_bind(server_conn, UIP_HTONS(3000));

  // etimer_set(&et, SEND_INTERVAL);
  // PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  
  broadcast_conn = udp_broadcast_new(UIP_HTONS(BROADCAST_PORT), NULL);
  udp_bind(broadcast_conn, UIP_HTONS(BROADCAST_PORT));


  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
