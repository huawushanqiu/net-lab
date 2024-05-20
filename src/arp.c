#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "buf.h"
#include "config.h"
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
  //初始化arp_pkt
  arp_pkt_t arp_pkt = arp_init_pkt;
  buf_init(&txbuf,sizeof(arp_pkt_t));
  arp_pkt.opcode16 = swap16(ARP_REQUEST);
  //注意下面这一行,arp_req的报文默认mac地址为全0,不需要更改target_mac！！！
  //不要和以太网帧的mac地址搞混了！！！
  //memcpy(arp_pkt.target_mac, ether_broadcast_mac, NET_MAC_LEN); 
  //下面看错了，最开始写的net_if_mac，引以为戒
  memcpy(arp_pkt.target_ip, target_ip, NET_IP_LEN);
  //初始化完成之后一并复制给txbuf
  arp_pkt_t *arp_hdr = (arp_pkt_t *)txbuf.data;
  memcpy(arp_hdr, &arp_pkt, sizeof(arp_pkt_t));
  ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
  arp_pkt_t arp_pkt = arp_init_pkt;
  buf_init(&txbuf, sizeof(arp_pkt_t));
  arp_pkt.opcode16 = swap16(ARP_REPLY);
  memcpy(arp_pkt.target_ip, target_ip, NET_IP_LEN);
  memcpy(arp_pkt.target_mac, target_mac, NET_MAC_LEN);
  //初始化完成后一并复制给txbuf
  arp_pkt_t *arp_hdr = (arp_pkt_t *)txbuf.data;
  memcpy(arp_hdr, &arp_pkt, sizeof(arp_pkt_t));
  ethernet_out(&txbuf, arp_hdr->target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
  if(buf->len < sizeof(arp_pkt_t)){
    return;
  }else{
    arp_pkt_t *arp_hdr = (arp_pkt_t *)buf->data;
    //注意下面几个swap16,之前写到这全忘了，引以为戒！！！
    if((arp_hdr->hw_type16 != swap16(ARP_HW_ETHER))
      || (arp_hdr->pro_type16 != swap16(NET_PROTOCOL_IP))
      || (arp_hdr->hw_len != NET_MAC_LEN)
      || (arp_hdr->pro_len != NET_IP_LEN)
      || ((arp_hdr->opcode16 != swap16(ARP_REQUEST)) && (arp_hdr->opcode16 != swap16(ARP_REPLY))))
    {
      return;
      //下面看错了，最开始写的pro_type16，引以为戒
    }else if(arp_hdr->opcode16 == swap16(ARP_REPLY)){
      //接受包为ARP_REPLY
      map_set(&arp_table, arp_hdr->sender_ip, arp_hdr->sender_mac);
      if(map_get(&arp_buf, arp_hdr->sender_ip)){
        //之前有没发出去的包
        buf_t *ip_buf = (buf_t *)map_get(&arp_buf, arp_hdr->sender_ip);
        //注意下面的NET_PROTOCOL_IP，这里是把之前没发出去的IP数据包发出去，所以不是ARP协议
        //ARP协议只有两类数据包，一类是ARP_REQUEST，一类是ARP_REPLY
        ethernet_out(ip_buf, arp_hdr->sender_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, arp_hdr->sender_ip);
      }
    }else{
      //接收包为ARP_REQUEST
      //注意这里也要进行一次填表,无论是request还是reply都需要填表
      //这里由于自己的if-else逻辑判断和指导书的逻辑不太一样，所以最初忘记填表了，引以为戒！！！
      map_set(&arp_table, arp_hdr->sender_ip, arp_hdr->sender_mac);
      //注意memcmp相等返回值为0
      if(!memcmp(arp_hdr->target_ip, net_if_ip, NET_IP_LEN)){
        arp_resp(arp_hdr->sender_ip, arp_hdr->sender_mac);
      }
    }
  }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
  uint8_t target_mac[NET_MAC_LEN];
  if(map_get(&arp_table, ip)){
    memcpy(target_mac, (uint8_t *)map_get(&arp_table, ip), NET_MAC_LEN);
    //这里也和上面是同样的道理
    ethernet_out(buf, target_mac, NET_PROTOCOL_IP);
  }else if(map_get(&arp_buf, ip)){
    //说明正在等待该ip回应arp请求
    ;
  }else{
    //没有找到ip对应的mac地址
    map_set(&arp_buf, ip, buf);
    arp_req(ip);
  }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}
