#include "net.h"
#include "icmp.h"
#include "ip.h"
#include "utils.h"
#include <stdint.h>

/**
 * @brief 发送icmp响应
 * 
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
  //icmp_resp的数据字段为icmp_req的数据字段,首部又是相同的，所以长度也是一样的
  buf_init(&txbuf, req_buf->len);
  icmp_hdr_t *icmp_resp = (icmp_hdr_t *) txbuf.data;
  //由于icmp_resp和icmp_req只有type和校验和不同，所以可以先拷贝再修改
  //bug：又犯了同样的错，应该复制的是data不是buf
  //又是bug,&txbuf.data是什么鬼写法
  memcpy(txbuf.data, req_buf->data, req_buf->len);
  icmp_resp->type = ICMP_TYPE_ECHO_REPLY;
  icmp_resp->checksum16 = 0;
  //sizeof的单位是字节
  //注意，icmp的校验和涵盖了整个报文
  //又是和上面一样的bug
  icmp_resp->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);
  ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
  if(buf->len < sizeof(icmp_hdr_t)){
    return;
  }else{
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *) buf->data;
    if(icmp_hdr->type == (uint8_t)ICMP_TYPE_ECHO_REQUEST){
      icmp_resp(buf, src_ip);
    }else{
      return;
    }
  }
}

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
  //差错报文数据部分为ip首部以及ip数据的前8个字节
  buf_init(&txbuf, sizeof(icmp_hdr_t) + sizeof(ip_hdr_t) + 8);
  icmp_hdr_t *icmp_hdr = (icmp_hdr_t *) txbuf.data;
  icmp_hdr->type = ICMP_TYPE_UNREACH;
  icmp_hdr->code = code;
  icmp_hdr->checksum16 = 0;
  //剩下的首部部分全部为零
  icmp_hdr->id16 = 0;
  icmp_hdr->seq16 = 0;
  //填写icmp数据部分
  uint8_t *tmp_data = txbuf.data;
  tmp_data += sizeof(icmp_hdr_t);
  //又是一个bug,这里拷贝的是data，不是recv_buf
  //这个问题很严重，因为没有首部接收方就找不到协议和进程端口号
  memcpy(tmp_data, recv_buf->data, sizeof(ip_hdr_t) + 8);
  //计算icmp校验和
  //又是和上面一样的bug
  icmp_hdr->checksum16 = checksum16((uint16_t *) txbuf.data, txbuf.len);
  ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init(){
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}
