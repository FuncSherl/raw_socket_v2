#include "socket_base.h"




//int socket_base::local_conf_valid = 0; //这是因为类的静态成员变量在使用前必须先初始化。
vector<local_conf>  socket_base::local;

socket_base::socket_base (int AF, int type, int proto) {
    socket_m = -1;
    sel_send_card = 0;
    sel_recv_card = 0;
    //ctor
    socket_m = socket (AF, type, proto);
    if (socket_m == -1) {
        perror ("socket_base:create socket error!");
        exit (1);
    }
    //bzero (&host_addr, sizeof (struct sockaddr_in));
    //bzero (&client_addr, sizeof (struct sockaddr_in));

    if (local.size() <= 0) {
        get_local_info (local);
        if (local.size() <= 0) {
            perror ("There is no network card available!");
            exit (1);
        } else {
            show_netcards();
        }
    }
}
int socket_base::ioctl_get_mac (struct ifreq * ifr) {
    /*
    *use 'struct ifreq' and ioctl to get the card's mac,the name should written in the ifr already
    */
    if (ioctl (socket_m, SIOCGIFHWADDR, ifr) == -1) {     //获取mac地址
        perror ("get mac error!");
        return -1;
    }
    return 0;
}
int socket_base::ioctl_get_index (struct ifreq * ifr) {
    /*
    *use 'struct ifreq' and ioctl to get the card's index,the name should written in the ifr already
    */
    if (ioctl (socket_m, SIOCGIFINDEX, ifr) == -1) {     //return index of card
        perror ("get index error!");
        return -1;
    }
    return 0;
}

int socket_base::ioctl_get_ip (struct ifreq * ifr) {
    /*
    *use 'struct ifreq' and ioctl to get the card's ip,the name should written in the ifr already
    */
    //printf("ifr in ip name;%s\n",ifr->ifr_name);
    if (ioctl (socket_m, SIOCGIFADDR, ifr) == -1) {     //get  ip address
        perror ("ioctl() get ip error");
        return -1;
    }
    return 0;
}

int socket_base::ioctl_get_mask (struct ifreq * ifr) {
    /*
    *use 'struct ifreq' and ioctl to get the card's mask,the name should written in the ifr already
    */
    if (ioctl (socket_m, SIOCGIFNETMASK, ifr) == -1) {    //get  mask
        perror ("ioctl() get mask error");
        return -1;
    }
    return 0;
}

int socket_base::ioctl_get_broadcast (struct ifreq * ifr) {
    /*
    *use 'struct ifreq' and ioctl to get the card's broadcast addr,the name should written in the ifr already
    */
    if (ioctl (socket_m, SIOCGIFBRDADDR, ifr) == -1) {
        perror ("ioctl() get broadcast addr error");
        return -1;
    }
    return 0;
}


int socket_base::get_local_info (vector<local_conf> & p) {
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[max_ether_len];
    const int sock = socket_m;
    local_conf tep_conf;

    ifc.ifc_len = sizeof (buf);
    ifc.ifc_buf = buf;
    if (ioctl (socket_m, SIOCGIFCONF, &ifc) == -1) {     //ioctl是设备驱动程序中对设备的I/O通道进行管理的函数,获取所有接口的清单
        perror ("ioctl error\n");
        return -1;
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof (struct ifreq));
    char szMac[64];
    int count = 0;
    for (; it != end; ++it) {
        //char *strcpy(char* dest, const char *src)
        //将name考到ifr里面去，后面查询用
        strcpy (ifr.ifr_name, it->ifr_name);

        if (ioctl (socket_m, SIOCGIFFLAGS, &ifr) == 0) {     //查询flag
            // don't count loopback,避免记录环路,仅仅记录up状态的
            if ( (! (ifr.ifr_flags & IFF_LOOPBACK))  && (ifr.ifr_flags & IFF_UP)) {

                strcpy ( (tep_conf).card_name, it->ifr_name);

///////////////////////////////////////////////////////////////////////////////////////////////
                if (!ioctl_get_index (&ifr)) {    //return index of card
                    tep_conf.index = ifr.ifr_ifindex;
                    //printf("get index:%d\n",socket_m);
                } else {
                    return -1;
                }
////////////////////////////////////////////////////////////////////////////////////////////////
                if (!ioctl_get_mac (&ifr)) {    // 获取mac地址
                    unsigned char * ptr ;
                    ptr = (unsigned char  *) &ifr.ifr_ifru.ifru_hwaddr.sa_data[0];
                    memcpy ( (tep_conf.mac), ptr, mac_len);

                    //printf("mac :%x\n",ptr[0]);
                    //printf("get index:%d\n",socket_m);
                } else {
                    return -1;
                }
////////////////////////////////////////////////////////////////////////////////////////////////////
                if (!ioctl_get_ip (&ifr)) {    //get  ip address
                    char *src_ip = inet_ntoa ( ( (struct sockaddr_in *) & (ifr.ifr_addr))->sin_addr);
                    strcpy ( (tep_conf).ip,   src_ip);
                    //printf("local ip:%s\n", src_ip);
                    //printf("get index:%d\n",socket_m);
                } else {
                    return -1;
                }
/////////////////////////////////////////////////////////////////////////////////////////////////
                if (!ioctl_get_mask (&ifr)) {   //SIOCGIFNETMASK mask
                    char *mas_tep = inet_ntoa ( ( (struct sockaddr_in*) & (ifr.ifr_netmask))->sin_addr);
                    strcpy (tep_conf.mask, mas_tep);
                } else {
                    return -1;
                }
////////////////////////////////////////////////////////////////////////////////////////////////
                if (!ioctl_get_broadcast (&ifr)) {   //broadcast
                    char *address = inet_ntoa ( ( (struct sockaddr_in *) &ifr.ifr_broadaddr)->sin_addr);
                    strcpy ( (tep_conf).ip_broadcast,   address);
                    //printf ("broad addr: %s \n", address);
                } else {
                    return -1;
                }

///////////////////////////////////////////////////////////////////////////////////////////////
                tep_conf.gate = getgateway (tep_conf.card_name);

///////////////////////////////////////////////////////////////////////////////////////////////////////////

                p.push_back(tep_conf);
                count++;
            }
        } else {
            perror ("get info error\n");
            return -1;
        }
    }
    return count;
}


uint32_t socket_base::getgateway() {
    FILE *fp;
    char buf[512];
    char cmd[128];
    char gateway[30];
    char *tmp;

    strcpy (cmd, "ip route");   //run ip route command
    fp = popen (cmd, "r");
    if (NULL == fp) {
        perror ("popen error");
        return -1;
    }
    while (fgets (buf, sizeof (buf), fp) != NULL) {
        tmp = buf;
        while (*tmp && (*tmp == ' '))
            ++ tmp;
        if (strncmp (tmp, "default", strlen ("default")) == 0)
            break;
    }
    sscanf (buf, "%*s%*s%s", gateway);
    //printf("default gateway:%s\n", gateway);
    pclose (fp);

    return inet_addr (gateway);
}

uint32_t socket_base::getgateway (const char * pNICName) {
    /*
    *otherwise we need use socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE) to get routing table from kernel,that's another question
    *since this can also work,so ....
    */
    char buffer[200] = { 0 };

    unsigned long bufLen = sizeof (buffer);

    unsigned long defaultRoutePara[4] = { 0 };
    FILE * pfd = fopen (PATH_ROUTE, "r");
    if (NULL == pfd) {
        return 0;
    }

    /*
    fgets,从文件结构体指针stream中读取数据，每次读取一行。读取的数据保存在buf指向的字符数组中，每次最多读取bufsize-1个字符
    （第bufsize个字符赋'\0'），如果文件中的该行，不足bufsize-1个字符，则读完该行就结束。
    */
    while (fgets (buffer, bufLen, pfd)) {
        sscanf (buffer, "%*s %x %x %x %*x %*x %*x %x %*x %*x %*x\n", (unsigned int *) &defaultRoutePara[1], (unsigned int *) &defaultRoutePara[0], (unsigned int *) &defaultRoutePara[3], (unsigned int *) &defaultRoutePara[2]);

        if (NULL != strstr (buffer, pNICName)) {
            //如果FLAG标志中有 RTF_GATEWAY
            if (defaultRoutePara[3] & RTF_GATEWAY) {
                uint32_t ip = defaultRoutePara[0];
                //snprintf(pGateway, len, "%d.%d.%d.%d", (ip & 0xff), (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff);
                return ip;
            }
        }

        memset (buffer, 0, bufLen);
    }

    fclose (pfd);
    pfd = NULL;
    return 0;
}

void socket_base::show_netcards() {
    cout<< ("Avalible net cards:\n");
    int num=0;
    for (local_iter i = local.begin(); i !=local.end(); i++) {
            /*
        printf ("NUM: %d\n", i);
        //printf("index %d: %s\n", local[i].index, local[i].card_name);
        printf ("NAME:%s\n", local[i].card_name);
        printf ("IP: %s\n", local[i].ip);
        printf ("BROADCAST: %s\n", local[i].ip_broadcast);
        printf ("MASK: %s\n", local[i].mask);
        printf ("GATE: %s\n", inet_ntoa (i2addr_in (local[i].gate)));
        printf ("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", local[i].mac[0] & 0xff, local[i].mac[1] & 0xff, local[i].mac[2] & 0xff, local[i].mac[3] & 0xff, local[i].mac[4] & 0xff, local[i].mac[5] & 0xff);
        printf ("\n");
        */
        cout<<"NUM: "<<num<<endl;
        cout<<"NAME: "<<i->card_name<<endl;
        cout<<"IP: "<<i->ip<<endl;
        cout<<"BROADCAST: "<<i->ip_broadcast<<endl;
        cout<<"MASK: "<<i->mask<<endl;
        cout<<"GATE: "<< inet_ntoa (i2addr_in (i->gate))<<endl;

        cout<<"MAC: ";
        for (int j=0;j<mac_len;j++) cout<<hex<<((i->mac)[j] & 0xff)<<":";

        cout<<endl<<endl;
        num++;
    }
}

int socket_base::get_socket() {
    return socket_m;
}

void socket_base::setsocket (int p) {
    if (socket_m > 0) close (socket_m);
    socket_m = p;
}

int socket_base::check_endin(){
    int i = 1;
    return *(char*)&i;   //返回1 是小端 否则大端
}

uint16_t socket_base::checksum (uint16_t* buffer, int size) {   //this size is char size(1Byte),not uint16_t(2Byte)

    unsigned long cksum = 0;
    //每16位相加
    while (size > 1)    {
        cksum += *buffer++;
        size -= sizeof (uint16_t);
    }
    //最后的奇数字节
    if (size){
        if (check_endin()==1)   cksum += * (uint8_t*) buffer;
        else {
                //printf("big endin detected!\n");
                int tep=(* (uint8_t*) buffer);
                cksum += tep<<8;
        }
    }
    while (cksum >> 16) {
        cksum = (cksum >> 16) + (cksum & 0xffff);     //将高16bit与低16bit相加
        //cksum += (cksum >> 16);
    }                        //将进位到高位的16bit与低16bit 再相加,确保高16位为0
    return ( (uint16_t) (~cksum));    //最后将结果取反,得到checksum
}

void socket_base::test_checksum() {

    printf ("size of my ip:%d\n", sizeof (struct my_ip));
    unsigned char tep[] = { 0x45, 0x00, 0x00, 0x31, 0x89, 0xF5, 0x00, 0x00, 0x6E, 0x06, 0x00, 0x00, 0xDE, 0xB7, 0x45, 0x5D, 0xC0, 0xA8, 0x00, 0xDC, 0xaa};

    int len=sizeof(tep);

    for (int i = 0; i < len; ++i) printf ("0x%x ", tep[i]);

    uint16_t t = checksum ( (uint16_t*) tep, len);
    printf ("cal chedksum:0x%x\n", t);

    my_ip* ip = (my_ip*) tep;
    ip->check_sum = t;
    for (int i = 0; i < len; ++i) printf ("0x%x ", tep[i]);

    printf ("add and check:0x%x\n", checksum ( (uint16_t*) tep, len));
}
/*

typedef struct my_ip{
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
}my_ip;
*/
void socket_base::form_ip (my_ip *ip, int datalen, int proto,  char *desip, char *srcip, int head_len, int version) {
    bzero (ip, sizeof (my_ip));
    ip->ver_hdlen = (version << 4 | sizeof (my_ip) / sizeof (unsigned long));
    ip->full_len = htons (datalen + head_len);
    ip->group_id = 1; //
    ip->timetolive = 64;
    ip->super_proto = proto & 0xff;
    ip->des_ip = inet_addr (desip);
    if (srcip == NULL) {
        ip->src_ip = inet_addr (local[sel_send_card].ip);
    } else {
        ip->src_ip = inet_addr (srcip);
    }
    ip->check_sum = checksum ( (uint16_t*) ip, sizeof (my_ip));
}

void socket_base::form_tcp (my_tcp *tcp, char *data, int data_len, char *src_ip, char *des_ip, int src_port, int des_port, int seq, int ack, char flag,  int hd_len, int win_size) {
    bzero (tcp, sizeof (my_tcp));

    tcp->des_port = htons (des_port);
    tcp->src_port = htons (src_port);

    tcp->hdlen_flag = (hd_len / 4 << 12 | flag);
    tcp->winsize = htons (win_size);
    tcp->ack = htonl (ack);
    tcp->tcp_sequ = htonl (seq);

    char bu[max_ether_len];
    bzero (bu, sizeof (bu));

    fake_hd * fh = (fake_hd*) bu;
    fh->proto = IPPROTO_TCP;
    fh->tcp_len = htons (hd_len + data_len);
    fh->src_ip = inet_addr (src_ip);
    fh->des_ip = inet_addr (des_ip);


    memcpy (bu + sizeof (fake_hd), tcp, sizeof (my_tcp));
    memcpy (bu + sizeof (fake_hd) + sizeof (my_tcp), data, data_len);

    tcp->check_sum = checksum ( (uint16_t*) bu, sizeof (fake_hd) + sizeof (my_tcp) + data_len);
}

void socket_base::show_ip (my_ip *p) {
    printf ("IP INFO:\n");
    printf ("ip addr: %s --> ", inet_ntoa (i2addr_in (p->src_ip)));
    printf ("%s\n", inet_ntoa (i2addr_in (p->des_ip)));
    printf ("Check Sum: 0x%x\n", checksum ( (uint16_t*) p, htons (p->full_len)));
}

void socket_base::show_tcp (my_tcp *p) {
    printf ("TCP INFO:\n'");
    printf ("port: %d --> %d \n", htons (p->src_port), htons (p->des_port));

}

uint32_t socket_base::local_ipstart() {//net seq
    uint32_t mask = htonl (inet_addr (local[sel_send_card].mask));
    uint32_t ip = htonl (inet_addr (local[sel_send_card].ip));
    ip &= mask;
    return htonl (ip);
}

uint32_t socket_base::local_ipend() {//net seq
    uint32_t mask = htonl (inet_addr (local[sel_send_card].mask));
    uint32_t ip = htonl (inet_addr (local[sel_send_card].ip));
    ip |= (~mask);
    return htonl (ip);
}

char *socket_base::rid_ip (char *p, my_ip*ip) {
    if (ip != NULL) memcpy (ip, p, sizeof (my_ip));
    my_ip *tp = (my_ip*) p;
    return p + ( (tp->ver_hdlen) & 0x0f) * 4;
}

char *socket_base::rid_tcp (char *p, my_tcp *tcp) {
    if (tcp != NULL) memcpy (tcp, p, sizeof (my_tcp));
    my_tcp * tp = (my_tcp*) p;
    return p + ( ( (tp->hdlen_flag) & 0xf0) >> 2);
}



uint32_t socket_base::getmyip (int index) {
    return inet_addr (local[index].ip);
}

void socket_base::my_swap_buffer (char *p1, char *p2, int len) {
    char tep;
    int i = 0;
    for (i = 0; i < len; i++) {
        tep = p1[i];
        p1[i] = p2[i];
        p2[i] = tep;
    }
}

int socket_base::my_comp_mac (char *a, char *b, int len) {   //1 for same, 0 for not
    int flag = len - 1;
    for (; flag >= 0; flag--)
        if (a[flag] != b[flag]) return 0;
    return 1;
}

int socket_base::ifoneofmy_mac (char *p) {   //-1 for not in , i for in
    for (int i = 0; i < local.size(); i++)
        if (my_comp_mac (p, local[i].mac)) return i;
    return -1;
}

int socket_base::ifoneofmy_ip (uint32_t p) {
    for (int i = 0; i <  local.size(); i++)
        if (p == inet_addr (local[i].ip)) return i;
    return -1;
}

int socket_base::get_freeport() {
    struct sockaddr_in sin;
    memset (&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons (0);
    sin.sin_addr.s_addr = htonl (INADDR_ANY);

    int fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (fd < 0) {
        perror ("socket_base:get_freeport error!");
        return 0;
    }
    if (bind (fd, (struct sockaddr *) &sin, sizeof (sin)) != 0) {
        perror ("sock_mac:get_freeport:bind() error");
        close (fd);
        return 0;
    }

    int len = sizeof (sin);
    if (getsockname (fd, (struct sockaddr *) &sin, (socklen_t*) &len) != 0) {
        perror ("socket_base: get_freeport:error");
        close (fd);
        return 0;
    }

    int port = sin.sin_port;
    if (fd != -1)
        close (fd);
    return port;
}

int socket_base::set_recv_card (int index) {
    sel_recv_card = index;
}
int socket_base::set_send_card (int index) {
    sel_send_card = index;
}


int socket_base::inwhichcard (uint32_t p) {

    for (int i = 0; i <  local.size(); i++) {
        uint32_t tep = inet_addr (local[i].mask);
        if (inet_addr (local[i].ip)  & tep == p & tep) return i;
    }
    return -1;
}

socket_base::~socket_base() {
    //dtor
    if (socket_m > 0) {
        close (socket_m);
    }
}
