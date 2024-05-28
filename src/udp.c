#include "udp.h"
#include "ip.h"
#include "icmp.h"

/**
 * @brief udp处理程序表
 * 
 */
map_t udp_table;

/**
 * @brief udp伪校验和计算
 * 
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dst_ip 目的ip地址
 * @return uint16_t 伪校验和
 */
static uint16_t udp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip)
{
    //这里先取出udp头部，后面要用到udp长度字段
    udp_hdr_t *udp_hdr = (udp_hdr_t *) buf->data;
    buf_add_header(buf, sizeof(udp_peso_hdr_t));
    //注意，暂存数据不能直接用指针，否则就变成同一个地址空间了
    //这里对ip头部所在的位置产生了误解，实际上IPv4的protocol和udp伪头部的protocol在同一个位置
    //之前我画蛇添足，因为二者相等，所以复制了udp伪头部和头部给暂存的ip头部，但是忘了暂存的ip头部
    //中的tos部分才是protocol，错误地把暂存的ip头部中的protocol给赋值给了udp伪头部，所以其实应该
    //把暂存ip的tos复制给protocol，但是还是不这样写了，太乱了
    //没想到在udp_out的时候被这种写法给坑了，严格来说是又被指导书误导了，
    //指导书上说udp伪头部的值来源于IPv4的头部，但是这显然是有问题的，当执行udp_out
    //的时候，根本就没到IP这一层，所以协议字段还没有被设置，值为零，这也太坑人了
    //但是指导书并没有给出udp_out的协议值怎么搞，看来这个值只能直接用宏定义了
    //或者加一层判断，协议值为0时表明正在out，此时采用宏定义
    ip_hdr_t tmp_ip_hdr;
    memcpy(&tmp_ip_hdr, buf->data - 8, sizeof(ip_hdr_t));
    udp_peso_hdr_t *udp_peso_hdr = (udp_peso_hdr_t *) buf->data;
    memcpy(udp_peso_hdr->src_ip, src_ip, NET_IP_LEN);
    memcpy(udp_peso_hdr->dst_ip, dst_ip, NET_IP_LEN);
    udp_peso_hdr->placeholder = 0;
    udp_peso_hdr->total_len16 = udp_hdr->total_len16;
    if(tmp_ip_hdr.protocol != 0){
        udp_peso_hdr->protocol = tmp_ip_hdr.protocol;
    }else{
        udp_peso_hdr->protocol = NET_PROTOCOL_UDP;
    }
    uint16_t udp_checksum = checksum16((uint16_t *)buf->data, buf->len);
    memcpy(buf->data - 8, &tmp_ip_hdr, sizeof(ip_hdr_t));
    buf_remove_header(buf, sizeof(udp_peso_hdr_t));
    return udp_checksum;
}

/**
 * @brief 处理一个收到的udp数据包
 * 
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    udp_hdr_t *udp_hdr = (udp_hdr_t *) buf->data;
    if(buf->len < sizeof(udp_hdr_t) 
    || buf->len < (size_t)(swap16(udp_hdr->total_len16))
    ){
        return;
    }else{
        uint16_t tmp_checksum = udp_hdr->checksum16;
        udp_hdr->checksum16 = 0;
        if(udp_checksum(buf, src_ip, net_if_ip) != tmp_checksum){
            return;
        }else{
            udp_hdr->checksum16 = tmp_checksum;
            //使用之前先转换大小端序
            uint16_t tmp_dst_port = swap16(udp_hdr->dst_port16);
            //注意这里传入的是指针，所以需要传入地址
            if(map_get(&udp_table, &tmp_dst_port) == NULL){
                //这里是否需要填写IPv4数据报头部存疑
                buf_add_header(buf ,sizeof(ip_hdr_t));
                icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
            }else{
                buf_remove_header(buf, sizeof(udp_hdr_t));
                //调用app处理函数
                udp_handler_t *app_handler = (udp_handler_t *)map_get(&udp_table, &tmp_dst_port);
                (*app_handler)(buf->data, buf->len, src_ip, swap16(udp_hdr->dst_port16));
            }
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_add_header(buf, sizeof(udp_hdr_t));
    udp_hdr_t *udp_hdr = (udp_hdr_t *) buf->data;
    //不确定这里是否需要转换大小端序
    udp_hdr->src_port16 = swap16(src_port);
    udp_hdr->dst_port16 = swap16(dst_port);
    udp_hdr->total_len16 = swap16((uint16_t)buf->len);
    udp_hdr->checksum16 = 0;
    udp_hdr->checksum16 = udp_checksum(buf, net_if_ip, dst_ip);
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 * 
 */
void udp_init()
{
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 * 
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 * 
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 * 
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}