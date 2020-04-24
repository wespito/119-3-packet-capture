#include <stdio.h>
#include <termio.h>
#include <unistd.h>
#include <pcap.h> //pcap library
#include <arpa/inet.h> //inet.ntoa
#include <netinet/in.h> //in_addr

pcap_t *handle; //handler
char *dev = "eth0"; //my network device
char errbuf[PCAP_ERRBUF_SIZE]; //errer message buffer
struct bpf_program fp; //filter structure
char filter_exp;// = "";//"port 80"; //filter representation
bpf_u_int32 mask; //subnet mask
bpf_u_int32 net; //ip address
struct pcap_pkthdr *header; //packet info
const u_char *packet; //actual?? packet
struct in_addr addr; // addr info


//***************packet capture***************
int title();
void filterSet();
void parsing();
int getch();
int kbhit();

#define ETHER_ADDR_LEN 6

struct sniff_ethernet { //erhernet sniffing structure
    u_char ether_dhost[ETHER_ADDR_LEN]; //destination MAC addr
    u_char ether_shost[ETHER_ADDR_LEN]; //source MAC addr
    u_short ether_type;
};


#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

struct sniff_ip{ //IP sniffing structure
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    #define IP_RF 0x8000
    #define IP_DF 0x4000
    #define IP_MF 0x2000
    #define IP_OFFMASK 0x1fff
    u_char ip_ttl;
    u_char ip_p; //IP protocol type
    u_short ip_sum;
    struct in_addr ip_dst; //destination IP addr
    struct in_addr ip_src; //source IP addr
};


typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport; //source TCP addr
    u_short th_dport; //destination TCP addr
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
    unsigned char fin:1;
    unsigned char syn:1;
    unsigned char rst:1;
    unsigned char psh:1;
    unsigned char ack:1;
    unsigned char urg:1;
    unsigned char ecn:1;
    unsigned char cwr:1;
};


#define SIZE_ETHERNET 14

struct sniff_ethernet *ethernet; //ethernet header
struct sniff_ip *ip; //ip header
struct sniff_tcp *tcp; //tcp header
char *payload; //payload

u_int size_ip;
u_int size_tcp;
//***************packet capture***************


int main(void) {

    title();

    return 0;
}

int title() {
    int i, key;

    do{
    printf("%c[1;35m", 27);
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("not found network device\n");
        return 0;
    }
    printf("Network Device Name : %s\n", dev);
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        printf("not fount device address\n");
        return 0;
    }
    addr.s_addr = net;
    printf("IP Address : %s\n", inet_ntoa(addr));
    addr.s_addr = mask;
    printf("Subnetmask : %s\n", inet_ntoa(addr));

    //***************packet capture***************
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("device open error\n");
        return 0;
    }
    if (pcap_compile(handle, &fp, &filter_exp, 0, net) == -1) {
        printf("filter error\n");
        filterSet();
        //return 0;
    }
    if (pcap_setfilter(handle, &fp) == -1) { //actual filtering
        printf("setting filter error\n");
        return 0;
    }

    printf("%c[1;33m", 27); //text color
    printf("\n\n\n");
    printf("\t\t\t***Packet Capture Tool***\n\n");
    printf("%c[1;32m", 27); //text color
    printf("\t\t\t<1> Capture Start\n\n");
    /*if(filter_exp == "") {
        //printf(" (Filter : None)\n\n");
    } else {
        printf(" (Filter : %s)\n\n", filter_exp);
    }*/
    printf("\t\t\t<2> Filter Setting\n\n");
    printf("\t\t\t<3> Exit\n\n");
    printf("\t\t\tEnter : ");
    scanf("%d", &i);


    switch (i){
        case 1:
            printf("%c[0m\n", 27);
            write(1, "\033[2J\033[1;1H", 11); //clear
            while(pcap_next_ex(handle, &header, &packet) >= 0) { //success = 1, time over = -0, errer = -1
                parsing();
            }
            break;
        case 2:
            write(1, "\033[2J\033[1;1H", 11); //clear
            filterSet();
            break;
        case 3:
            return 0;
            break;
    }
}while(1); //end of while
    return 0;
}

void filterSet(){
    int i = 0;
    char str[100];
    printf("\n\n\n\n");
    if(filter_exp == NULL || filter_exp == "") {
        printf("\t\t\t(Applied Filter : None)\n");
    } else {
        printf("\t\t\t(Applied Filter : %s)\n", &filter_exp);
    }
    printf("\t\t\tEnter Filter : ");
    scanf("%s", &filter_exp);


    write(1, "\033[2J\033[1;1H", 11); //clear
    printf("\n\n\n\n");
    printf("\t\t\t(Applied Filter : %s)\n", &filter_exp);
    printf("\t\t\tPress ESC Key to Continue");

    while (i != 27) {
        i = kbhit();
    }

    //fflush(stdin);
    write(1, "\033[2J\033[1;1H", 11); //clear
}

void parsing() {
    int i, payload_len;


    //[2]************************************************************
    printf("===============================================================\n");
    ethernet = (struct sniff_ethernet*)(packet);
    printf("MAC source address : ");
    for(i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x ", ethernet->ether_shost[i]);
    }
    printf("\nMAC destination adderss : ");
    for(i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x ", ethernet->ether_dhost[i]);
    }

    //[3]************************************************************

    //printf("Packet Length : %s\n", ntohs(ip->ip_len)+14);
    //printf("TTL : %s\n", ip->ip_ttl);

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) *4;
    printf("\nIP source address %s\n", inet_ntoa(ip->ip_src));
    printf("IP destination address : %s\n", inet_ntoa(ip->ip_dst));
    printf("Protocol ID : %d ", ip->ip_p);


    if(ip->ip_p==1){
        printf("%c[1;35m", 27); //text color
        printf("(ICMP)");
    } else if(ip->ip_p==2){
        printf("%c[1;34m", 27); //text color
        printf("(IGMP)");
    } else if(ip->ip_p==6){
        printf("%c[1;33m", 27); //text color
        printf("(TCP)");
    } else if(ip->ip_p==17){
        printf("%c[1;32m", 27); //text color
        printf("(UDP)");
    }
    printf("%c[0m\n", 27);
    //printf("\n");

    //[3]************************************************************
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) *4;
    printf("Source port : %d\n", ntohs(tcp->th_sport));
    printf("destination port : %d\n", ntohs(tcp->th_dport));

    if(ip->ip_p==6 && (tcp->cwr||tcp->ecn||tcp->urg||tcp->ack||tcp->psh||tcp->rst||tcp->syn||tcp->fin)) {
        printf("Flag :");
        printf("%c[1;34m", 27); //text color
        if(ntohs(tcp->cwr))
        {
                printf(" CWR ");
        }
        if(ntohs(tcp->ecn))
        {
                printf(" ENC ");
        }
        if(ntohs(tcp->urg))
        {
                printf(" URG ");
        }
        if(ntohs(tcp->ack))
        {
                printf(" ACK ");
        }
        if(ntohs(tcp->psh))
        {
                printf(" PUSH ");
        }
        if(ntohs(tcp->rst))
        {
                printf(" RST ");
        }
        if(ntohs(tcp->syn))
        {
                printf(" SYN ");
        }
        if(ntohs(tcp->fin))
        {
                printf(" FIN ");
        }
        printf("%c[0m\n", 27);
    }

    //int j;
    payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    payload_len = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if(payload_len == 0) printf("No payload data");
    else {
        printf("Payload data : \n");
        for(int i = 1; i < payload_len; i++) {
            //j++;
            if(i>32) { printf(" ... \n"); break; }
            printf("%02x", payload[i - 1]);
            if(i%8 == 0) printf(" ");
            if(i%16 == 0) printf("\n");
        }
    }
    printf("\n");//-------------------------------------------------\n");
    //fclose(fp);
}

int getch(){
    int ch;
    struct termios buf, save;
    tcgetattr(0,&save);
    buf = save;
    buf.c_lflag &= ~(ICANON|ECHO);
    buf.c_cc[VMIN] = 1;
    buf.c_cc[VTIME] = 0;
    tcsetattr(0, TCSAFLUSH, &buf);
    ch = getchar();
    tcsetattr(0, TCSAFLUSH, &save);
    return ch;
}

int kbhit(){
    struct termios oldt, newt;
    int ch;
    tcgetattr( STDIN_FILENO, &oldt );
    newt = oldt;
    newt.c_lflag &= ~( ICANON | ECHO );
    tcsetattr( STDIN_FILENO, TCSANOW, &newt );
    ch = getchar();
    tcsetattr( STDIN_FILENO, TCSANOW, &oldt );
    return ch;
}

