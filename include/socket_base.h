#ifndef SOCKET_BASE_H
#define SOCKET_BASE_H

#include "socket_structs.h"

typedef vector<local_conf>::iterator local_iter;

/*
//填充IP报头
　ipHeader.h_verlen = (4 << 4 | sizeof(ipHeader) / sizeof(unsigned long));
　// ipHeader.tos=0;
　ipHeader.total_len = htons(sizeof(ipHeader) + sizeof(tcpHeader));
　ipHeader.ident = 1;
　ipHeader.frag_and_flags = 0;
　ipHeader.ttl = 128;
　ipHeader.proto = IPPROTO_TCP;
　ipHeader.checksum = 0;
　ipHeader.sourceIP = inet_addr("localhost");
　ipHeader.destIP = desIP;



　//填充TCP报头
　tcpHeader.th_dport = htons(desPort);
　tcpHeader.th_sport = htons(SOURCE_PORT); //源端口号
　tcpHeader.th_seq = htonl(0x12345678);
　tcpHeader.th_ack = 0;
　tcpHeader.th_lenres = (sizeof(tcpHeader) / 4 << 4 | 0);
　tcpHeader.th_flag = 2; //标志位探测，2是SYN
　tcpHeader.th_win = htons(512);
　tcpHeader.th_urp = 0;
　tcpHeader.th_sum = 0;


　//计算校验和
　memcpy(szSendBuf, &psdHeader, sizeof(psdHeader));
　memcpy(szSendBuf + sizeof(psdHeader), &tcpHeader, sizeof(tcpHeader));
　tcpHeader.th_sum = checksum((unsigned short*)szSendBuf, sizeof(psdHeader) + sizeof
(tcpHeader));
　
　memcpy(szSendBuf, &ipHeader, sizeof(ipHeader));
　memcpy(szSendBuf + sizeof(ipHeader), &tcpHeader, sizeof(tcpHeader));
　memset(szSendBuf + sizeof(ipHeader) + sizeof(tcpHeader), 0, 4);
　ipHeader.checksum = checksum((unsigned short*)szSendBuf, sizeof(ipHeader) + sizeof
(tcpHeader));
*/

class socket_base {
public:
    socket_base (int AF = AF_INET, int type = SOCK_DGRAM, int proto = IPPROTO_IP);
    //
    virtual ~socket_base();

    uint16_t checksum (uint16_t* buffer, int size); //this size is char size


    void setsocket (int p);
    void form_ip (my_ip *ip, int datalen, int proto,  char *desip, char *srcip = NULL, int head_len = 20, int version = 4);
    void form_tcp (my_tcp *tcp, char *data, int data_len, char *src_ip, char *des_ip, int src_port, int des_port, int seq, int ack, char flag, int hd_len = 20, int win_size = max_ether_len);
    void show_ip (my_ip *p);
    void show_tcp (my_tcp *p);
    void show_netcards();
    void my_swap_buffer (char *p1, char *p2, int len);
    void test_checksum();


    uint32_t local_ipstart();//net_sequence
    uint32_t local_ipend();//net sequence
    uint32_t getgateway();
    uint32_t getgateway (const char * pNICName);
    uint32_t getmyip (int index = 0);


    char *rid_ip (char *p, my_ip*ip = NULL);
    char *rid_tcp (char *p, my_tcp *tcp = NULL);



    int get_socket();
    int my_comp_mac (char *a, char *b, int len = mac_len);
    int ifoneofmy_mac (char *p);
    int ifoneofmy_ip (uint32_t p);
    int inwhichcard (uint32_t p);
    int get_freeport();
    int ioctl_get_index (struct ifreq * ifr);
    int ioctl_get_mac (struct ifreq * ifr);
    int ioctl_get_mask (struct ifreq * ifr);
    int ioctl_get_ip (struct ifreq * ifr);
    int ioctl_get_broadcast (struct ifreq * ifr);
    int check_endin();
    int get_local_info (vector<local_conf> & p);


    virtual int set_recv_card (int index = 0);
    virtual int set_send_card (int index = 0);

//************************************************************************//
    //struct sockaddr_in host_addr, client_addr;

    //static int local_conf_valid;//这是因为类的静态成员变量在使用前必须先初始化。
    static vector<local_conf> local;

    int sel_send_card, sel_recv_card;


//************************************************************************//
protected:


private:
    int socket_m;

};


#endif // SOCKET_BASE_H
