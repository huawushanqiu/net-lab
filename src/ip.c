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
#include <string.h>
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
  ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
  if(buf->len < sizeof(ip_hdr_t)){
    return;
  }else{
    //对于检查条件需要哪些还有疑问，对于最后是否为buf->len还有疑问
    //没想到问题居然在这里，不等号方向反了，实际上这也是没有去理解这个不等式的含义造成的问题
    //这里居然有两个错，一是符号反了，二是比较时没有还原成小端序，
    //因为比较操作在硬件层面，所以要变成小端序，只能说对大小端序的理解还大有问题
    //又发现一个问题，小于等于的反面是大于
    if((ip_hdr->version != IP_VERSION_4) || (((size_t)swap16(ip_hdr->total_len16)) > buf->len)){
      return;
    }else{
      uint16_t tmp_hdr_checksum = ip_hdr->hdr_checksum16;
      //注意将原首部长暂时设为0
      ip_hdr->hdr_checksum16 = 0;
      //转型为uint16_t类型指针，单位为字节，原单位为4字节，所以需要乘4
      if(checksum16((uint16_t *)ip_hdr, (size_t)(IP_HDR_LEN_PER_BYTE * ip_hdr->hdr_len)) != tmp_hdr_checksum){
        return;
      }else{
        ip_hdr->hdr_checksum16 = tmp_hdr_checksum;
        //又是一个bug,memcmp相等时为零！！！
        if(memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN)){
          return;
        }else{
          //test的逻辑好像不太一样，是先去掉padding再判断icmp_unreachable
          //坑死人的大端序，真是无处不在
          if(buf->len > ((size_t)swap16(ip_hdr->total_len16))){
            buf_remove_padding(buf, buf->len - ((size_t)swap16(ip_hdr->total_len16)));
          }
          //指导书上一句icmp_unreachable太误导人了，那句话写在最后一步，
          //但是在最后一步buf都被改得面目全非了
          if((ip_hdr->protocol != NET_PROTOCOL_ICMP) &&
            // (ip_hdr->protocol != NET_PROTOCOL_TCP) &&
             (ip_hdr->protocol != NET_PROTOCOL_UDP)
            ){
            icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
            return;
          }
          //终于找到你了，可恶的bug，被你坑了整整两天，因为你我学会了如何调试
          //真的必须清楚每一个参数的类型和含义，这里看见个len就没反应过来，
          //结果这个鬼数据居然要乘4,必须长记性，必须清楚每个变量的含义
          buf_remove_header(buf, (size_t)(IP_HDR_LEN_PER_BYTE * ip_hdr->hdr_len));
          //真的难绷，连着两行坑我两次，这个net_in的src为什么兼具两个含义？
          //最坑的是你传个mac进来又不用，src又有两个含义，这不就是误导人去写mac吗
          net_in(buf, ip_hdr->protocol, ip_hdr->src_ip);
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
  buf_add_header(buf, sizeof(ip_hdr_t));
  ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
  //填写头部字段
  ip_hdr->version = IP_VERSION_4;
  ip_hdr->hdr_len = 5;
  ip_hdr->tos = 0;
  //此时buf->len已经加了20
  ip_hdr->total_len16 = buf->len;
  //buf->len的类型size_t不太清楚长度，所以先赋值再swap16
  ip_hdr->total_len16 = swap16(ip_hdr->total_len16);
  //注意int是32位，不能直接用swap，应该先转成16位
  ip_hdr->id16 = swap16((uint16_t)id);
  //这里的DF不知道是不是默认为0
  //注意大端序的变换
  ip_hdr->flags_fragment16 = (mf << 5) + ((offset / 8) << 8) + ((offset / 8) >> 8);
  ip_hdr->ttl = 64;
  ip_hdr->protocol = protocol;
  ip_hdr->hdr_checksum16 = 0;
  memcpy(ip_hdr->src_ip,net_if_ip,NET_IP_LEN);
  memcpy(ip_hdr->dst_ip,ip,NET_IP_LEN);
  //checksum不用变为大端序，因为它就是大端序的数据计算出来的
  ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, (size_t)(IP_HDR_LEN_PER_BYTE * ip_hdr->hdr_len));
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
    //又犯了复制buf的错，是复制data不是复制buf！！！
    memcpy(ip_buf.data, buf->data, max_ip_load);
    ip_fragment_out(&ip_buf, ip, protocol, id, offset, 1);
    //实际偏移值为offset乘8,所以要除以8 
    //错啦！offset就是实际偏移值！！！flags_fragment16中的位偏移才需要除以8！！！
    offset += max_ip_load;
    buf->len -= max_ip_load;
    buf->data += max_ip_load; 
  }
  //这里无论是剩下的还是原本就没超过max_ip_load的，可以合并到一块写
  buf_init(&ip_buf, buf->len);
  //和上面一样的错，是复制data不是buf
  memcpy(ip_buf.data, buf->data, buf->len);
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
