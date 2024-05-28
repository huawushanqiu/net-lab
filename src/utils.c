#include "utils.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
/**
 * @brief ip转字符串
 * 
 * @param ip ip地址
 * @return char* 生成的字符串
 */
char *iptos(uint8_t *ip)
{
    static char output[3 * 4 + 3 + 1];
    sprintf(output, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return output;
}

/**
 * @brief mac转字符串
 * 
 * @param mac mac地址
 * @return char* 生成的字符串
 */
char *mactos(uint8_t *mac)
{
    static char output[2 * 6 + 5 + 1];
    sprintf(output, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return output;
}

/**
 * @brief 时间戳转字符串
 * 
 * @param timestamp 时间戳
 * @return char* 生成的字符串
 */
char *timetos(time_t timestamp)
{
    static char output[20];
    struct tm *utc_time = gmtime(&timestamp);
    sprintf(output, "%04d-%02d-%02d %02d:%02d:%02d", utc_time->tm_year + 1900, utc_time->tm_mon + 1, utc_time->tm_mday, utc_time->tm_hour, utc_time->tm_min, utc_time->tm_sec);
    return output;
}

/**
 * @brief ip前缀匹配
 * 
 * @param ipa 第一个ip
 * @param ipb 第二个ip
 * @return uint8_t 两个ip相同的前缀长度
 */
uint8_t ip_prefix_match(uint8_t *ipa, uint8_t *ipb)
{
    uint8_t count = 0;
    for (size_t i = 0; i < 4; i++)
    {
        uint8_t flag = ipa[i] ^ ipb[i];
        for (size_t j = 0; j < 8; j++)
        {
            if (flag & (1 << 7))
                return count;
            else
                count++, flag <<= 1;
        }
    }
    return count;
}

/**
 * @brief 计算16位校验和
 * 
 * @param buf 要计算的数据包
 * @param len 要计算的长度
 * @return uint16_t 校验和
 */
uint16_t checksum16(uint16_t *data, size_t len)
{
  //指导书上说最后可能剩下8bit,但是首部长度应该是以32bit为单位，不明白为什么会有这种情况
  //按照我的理解长度肯定是16bit的倍数
  //写到udp才发现为什么要考虑8bit，ip头部一定为16的整数倍
  //而icmp的整个数据包长度也一定为16的整数倍
  //只有udp存在单独8bit，这时需要填充8bit的0，而tcp/ip规定大端序，
  //所以相当于将最后8位左移8位再相加
  uint32_t sum = 0;
  //for循环还是以16bit为单位
  for(int i = 0; i < len / 2; i++){
    sum += *data;
    data++;
  }
  //最后判断len是否剩下8bit，其实是udp专属（在这个实验中）
  if(len % 2 == 1){
    //先取出这8位，然后再转型为16位，最后再进行位移，之后相加
    // uint16_t last_data = (uint16_t)(*(uint8_t *)data);
    // last_data = last_data << 8;
    // sum += last_data;
    //不是，指导书的话也太误解人了吧，还以为填充0字节是要把最后8位变成高8位，
    //结果按checksum的实现方式来看，根本就不需要填充什么东西，被坑了半天
    sum += *(uint8_t *)data;
  }
  //接下来判断高16位是否为0
  //对于uint是否为无符号数存疑
  uint16_t sum_high = sum >> 16;
  uint16_t sum_low = (sum << 16) >> 16;
  while(sum_high != 0){
    sum = sum_high + sum_low;
    sum_high = sum >> 16;
    sum_low = (sum << 16) >> 16;
  }
  //取反
  sum_low = ~ sum_low; 
  return sum_low;
}
