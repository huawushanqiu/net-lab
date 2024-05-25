#include "buf.h"
#include "config.h"
#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"
#include "utils.h"
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

//ip数据报标识id 
uint8_t id = 0;
/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
  if(buf->len < sizeof(ip_hdr_t)){
    return;
  }else{
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    //对于检查条件需要哪些还有疑问，对于最后是否为buf->len还有疑问
    if((ip_hdr->version != IP_VERSION_4) || (ip_hdr->total_len16 <= buf->len)){
      return;
    }else{
      uint16_t tmp_hdr_checksum = ip_hdr->hdr_checksum16;
      //注意将原首部长暂时设为0
      ip_hdr->hdr_checksum16 = 0;
      //转型为uint16_t类型指针，单位为字节，原单位为4字节，所以需要乘4
      if(checksum16((uint16_t *)ip_hdr, IP_HDR_LEN_PER_BYTE * ip_hdr->hdr_len) != tmp_hdr_checksum){
        return;
      }else{
        ip_hdr->hdr_checksum16 = tmp_hdr_checksum;
        if(!memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN)){
          return;
        }else{
          if(buf->len > ip_hdr->total_len16){
            buf_remove_padding(buf, buf->len - ip_hdr->total_len16);
          }
          buf_remove_header(buf, ip_hdr->hdr_len);
          net_in(buf, ip_hdr->protocol, src_mac);
          //TODO:icmp不可达信息
        }
      }
    }
  }

}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
  //tcp/ip协议统一按大端序存储，这里大端序的作用于为所有字段，或者说属性
  //是一个完整的数，像数组之类的就不算，数组内部的元素才算,以字节为单位
  //8位不变，16位，32位甚至更多的都要变
  //ip头部长度固定为20
  buf_add_header(buf, 20);
  ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
  //填写头部字段
  ip_hdr->version = IP_VERSION_4;
  ip_hdr->hdr_len = 5;
  ip_hdr->tos = 0;
  //此时buf->len已经加了20
  ip_hdr->total_len16 = buf->len;
  //buf->len的类型size_t不太清楚长度，所以先赋值再swap16
  ip_hdr->total_len16 = swap16(ip_hdr->total_len16);
  ip_hdr->id16 = swap16(id);
  //这里的DF不知道是不是默认为0
  //注意大端序的变换
  ip_hdr->flags_fragment16 = (mf << 5) + ((offset / 8) << 8) + ((offset / 8) >> 8);
  ip_hdr->ttl = 64;
  ip_hdr->protocol = protocol;
  ip_hdr->hdr_checksum16 = 0;
  memcpy(ip_hdr->src_ip,net_if_ip,NET_IP_LEN);
  memcpy(ip_hdr->dst_ip,ip,NET_IP_LEN);
  //checksum不用变为大端序，因为它就是大端序的数据计算出来的
  ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, IP_HDR_LEN_PER_BYTE * ip_hdr->hdr_len);
  arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
  //ip头部固定为20，不考虑可变长度
  size_t max_ip_load = ETHERNET_MAX_TRANSPORT_UNIT - 20;
  uint16_t offset = 0;
  buf_t ip_buf;
  //把buf->data首地址和buf->len存起来，最后再还原
  uint8_t *tmp_data = buf->data;
  size_t tmp_len = buf->len;
  while(buf->len > max_ip_load){
    buf_init(&ip_buf, max_ip_load);
    buf_copy(&ip_buf, buf, max_ip_load);
    //这里需要注意将ip_buf的len设置为max_ip_load，否则就成了buf的长度！！
    ip_buf.len = max_ip_load;
    ip_fragment_out(&ip_buf, ip, protocol, id, offset, 1);
    //实际偏移值为offset乘8,所以要除以8 
    //错啦！offset就是实际偏移值！！！flags_fragment16中的位偏移才需要除以8！！！
    offset += max_ip_load;
    buf->len -= max_ip_load;
    buf->data += max_ip_load; 
  }
  //这里无论是剩下的还是原本就没超过max_ip_load的，可以合并到一块写
  buf_init(&ip_buf, buf->len);
  buf_copy(&ip_buf, buf, buf->len);
  ip_fragment_out(&ip_buf, ip, protocol, id, offset, 0);
  //最后要注意id++
  id++;
  //还原buf->data的首地址和buf->len 
  buf->data = tmp_data;
  buf->len = tmp_len;
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}
