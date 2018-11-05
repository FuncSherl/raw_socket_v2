
#ifndef SOCK_FUNS_H_MY
#define SOCK_FUNS_H_MY


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <errno.h>
#include <sys/wait.h>
#include <time.h>
#include <fcntl.h>
#include <net/route.h>


#include <iostream>
#include <string>
#include <vector>

using namespace std;


/*
1、函数之间传递数据均为本地序列，也即用小端法，hton*和ntoh*的实现是一致的
2、使用c++操作、
3、由mac->net(ip)->trans(port)->...
*/

#define PATH_ROUTE ("/proc/net/route")


#define max_ether_len ( 1500)
#define mac_len   ( 6)
#define ip_len (4)
#define max_card_num (10)
#define mac_send_persec (100)

#define MAX_LISTEN_NUM (2)

#define BROADCAST_ADDR  {0xff,0xff,0xff,0xff,0xff,0xff}

#define i2addr_in(add) (*((struct in_addr*)&add))

#pragma pack (1)//编译器将按照n个字节对齐
typedef struct my_mac {
    uint8_t des[mac_len];//destination mac address?all 1?
    uint8_t src[mac_len];//source mac address
    uint16_t type;//0x0806->arp; ox0800->ip
} my_mac;

typedef struct my_arp {
    uint16_t hd_type;//harware type:1->ethernet
    uint16_t pro_type;//proto type:0x0800->ip
    uint8_t mac_length;//mac length  6
    uint8_t ip_length;//ip length  4
    uint16_t op_type;//operation type:1->arp request;2->arp response


    uint8_t src_mac[mac_len];//source mac address
    uint32_t src_ip;//source ip address
    uint8_t des_mac[mac_len];//destination mac address:all zero in arp request
    uint32_t des_ip;//destination ip address

} my_arp;


typedef struct my_ip {
    uint8_t ver_hdlen;//version and head length
    uint8_t ser_type;//service type
    uint16_t full_len;//full length of this packet
    uint16_t group_id;//
    uint16_t tag_seg;//tag(3) and differ of segment(13)
    uint8_t timetolive;//
    uint8_t super_proto;//
    uint16_t check_sum;
    uint32_t src_ip;
    uint32_t des_ip;
} my_ip;

typedef struct my_tcp {
    uint16_t src_port;
    uint16_t des_port;
    uint32_t tcp_sequ;//tcp sequence
    uint32_t ack;//ack num
    uint16_t hdlen_flag;//head length(4)+remain(6)+flag(6)
    uint16_t winsize;//window size
    uint16_t check_sum;//tcp check sum
    uint16_t urge;//if urge
} my_tcp;

typedef struct fake_hd {
    uint32_t src_ip;
    uint32_t des_ip;
    uint8_t zero;
    uint8_t proto;
    uint16_t tcp_len;
} fake_hd;

#pragma pack ()//取消自定义字节对齐方式
#define ipstr_len 64


//保存local网卡信息，可能有多个
typedef struct {//pc's para
    char ip[ipstr_len];
    char ip_broadcast[ipstr_len];
    char mask[ipstr_len];
    uint32_t gate;
    char mac[mac_len];
    int index;
    char card_name[IFNAMSIZ];
} local_conf;


typedef struct {//recv arp info
    uint32_t ip;
    char mac[mac_len];
} tar_info;



static int com_ip(tar_info a, tar_info b) {//no reference in c
    return htonl(a.ip) < htonl(b.ip);
};



#endif
