#include "ethernet.h"
#include "buf.h"
#include "config.h"
#include "net.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
#include <stdint.h>
/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
  /*
   *大小端序的转换只存在于数据链路层和网络层之间，
   *由于TCP/IP规定字节序为大端序，这就相当于规范了网络层
   *及其之上的字节序，所以只需要考虑数据链路层的字节序。
   *至于哪些数据需要考虑字节序，首先，数据本身不需要考虑字节序，
   *因为数据对于数据链路层没有意义，我们只需要考虑会用到哪些数据，
   *这些数据就需要转换字节序，例如protocol。至于mac地址，由于mac地址
   *只会被数据链路层使用，而不会被网络层使用，所以不需要转换
   */
  if(buf->len < sizeof(ether_hdr_t)){
    return;
  }
  ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
  uint16_t protocol = swap16(hdr->protocol16);
  uint8_t *src = hdr->src;
  buf_remove_header(buf, sizeof(ether_hdr_t));
  net_in(buf,protocol,src);
}
/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
  if(buf->len < ETHERNET_MIN_TRANSPORT_UNIT){
    buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT - buf->len);
  }
  buf_add_header(buf, sizeof(ether_hdr_t));
  ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
  memcpy(hdr->src,net_if_mac,NET_MAC_LEN);
  memcpy(hdr->dst,mac,NET_MAC_LEN);
  hdr->protocol16 = swap16((uint16_t)protocol);
  driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 * 
 */
void ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
