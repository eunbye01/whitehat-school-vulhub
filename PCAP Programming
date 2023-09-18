#include <stdio.h> // 표준 입력과 출력을 위한 헤터 파일을 포함함
#include <pcap.h> // libcap 라이브러리를 사용하기 위한 헤더 파일을 포함함,
//이 라이브러리는 패킷 캡처와 관련된 기능을 제공함

#include <netinet/ip.h> //IP 헤더를 다루기 위한 헤더 파일을 포함함
#include <netinet/tcp.h> // TCP 헤더를 다루기 위한 헤더 파일을 포함함

// 이 구조체는 이더넷 헤더의 정보를 저장함, 이더넷 헤더는 네트워크 패킷의 맨 앞부분에 위치하며
// 목적지 MAC주소와 출발지 MAS 주소, 패킷의 유형을 포함함
//이 정보들은 네트워크 장치 간에 패킷을 전송할 때 사용됨
struct eth_header {
    unsigned char dst_mac[6]; //목적지 MAC 주소를 저장하는 6바이트 배열 
    unsigned char src_mac[6]; //출발지 MAC 주소를 저장하는 6바이트의 배열
    unsigned short ether_type; //이더넷 타입을 나타내는 2바이트의 정수, 이 값은 패킷의 유형을 나타냄
};

// 패킷을 캡처(PCAP)하고 해당 패킷의 Ethernet, IP, TCP 헤더 정보를 추출하여 
//출력하는 패킷 핸들러 함수인 'packet_handler'를 정의한 것
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // 패킷의 시작 부분은 이더넷 헤더, 'eth_hdr' 구조체 포인터를 생성하고
    //패킷의 시작 주소를 가리키도록 설정함
    struct eth_header *eth_hdr = (struct eth_header *)packet;

    // 이더넷 헤더 다음에는 IP헤더가 있음, IP헤더의 시작 주소를 계산하기 위해
    //'sizeod(struct eth_header)'만큼 이동하고 'ip_hdr' 구초제 포인터로 
    //형변환하여 IP 헤더를 가리키도록 설정함
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct eth_header));
    int ip_hdr_len = ip_hdr->ip_hl * 4; // IP 헤더의 길이는 헤더 길이 필드('ip_hl')에 4를 곱하여 계산, 
    //이 값은 IP 헤더의 바이트 단위 길이를 나타냄

    //IP 헤더 다음에는 TCP 헤더가 존재, TCP 헤더의 시작 주소를 계산하기 위해 
    //'sizeof(struct eth_header)와 'ip_hdr_len' 만큼 이동하고, 'tcp_hdr' 구조체 포인터로 
    // 형변환하여 TCP 헤더를 가리키도록 설정함
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct eth_header) + ip_hdr_len);

    // TCP 헤더 다음에는 데이터가 존재, 데이터의 시작 주소를 계산하기 위해 
    //'sizeof(struct eth_header), 'ip_hdr_len' 그리고 'th_off' 필드 값에
    //4를 곱하여 계산하고, 'data' 포인터로 형변환하여 데이터를 가리키도록 설정함
    unsigned char *data = (unsigned char *)(packet + sizeof(struct eth_header) + ip_hdr_len + tcp_hdr->th_off * 4);

    // 데이터의 길이는 패킷의 총 길이('pkthdr->len')에서 이더넷 헤더, IP 헤더, TCP 헤더의 길이를 빼서 계산함
    int data_len = pkthdr->len - (sizeof(struct eth_header) + ip_hdr_len + tcp_hdr->th_off * 4);

    // 'eth_hdr'구조체에서 출발지 MAC 주소 가져와 각 바이트별로 16진수로 출력
    printf("Ethernet Header, Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->src_mac[0], eth_hdr->src_mac[1], eth_hdr->src_mac[2],
           eth_hdr->src_mac[3], eth_hdr->src_mac[4], eth_hdr->src_mac[5]);

    // 'eth_hdr'구조체에서 목적지 MAC 주소 가져와 각 바이트별로 16진수로 출력
    printf("Ethernet Header, Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->dst_mac[0], eth_hdr->dst_mac[1], eth_hdr->dst_mac[2],
           eth_hdr->dst_mac[3], eth_hdr->dst_mac[4], eth_hdr->dst_mac[5]);

    // 'ip_hdr' 구조체에서 출발지 IP 주소를 가져와 문자열 형태로 출력
    printf("IP Header, Source IP: %s\n", inet_ntoa(ip_hdr->ip_src));

    // 'ip_hdr' 구조체에서 목적지 IP 주소를 가져와 문자열 형태로 출력
    printf("IP Header, Destination IP: %s\n", inet_ntoa(ip_hdr->ip_dst));

    // 'tcp_hdr' 구조체에서 출발지 포트를 가져와 출력
    printf("TCP Header, Source Port: %d\n", ntohs(tcp_hdr->th_sport));

    // 'tcp_hdr' 구조체에서 목적지 포트를 가져와 출력
    printf("TCP Header, Destination Port: %d\n", ntohs(tcp_hdr->th_dport));

    // 메시지 출력 (최대 16바이트까지 출력)
    int max_print_len = 16; //최대 출력할 바이트 수를 설정

    // 데이터를 출력할 길이를 저장함, 최대 16바이트까지 출력하게 됨
    int print_len = data_len > max_print_len ? max_print_len : data_len;

    //출력되는 메시지의 시작 부분, 출력되는 데이터의 길이가 몇 바이트인지 알려줌
    printf("Message (First %d Bytes): ", print_len);

    for(int i = 0; i < print_len; i++) {
        printf("%02x ", data[i]); //data[i]는 패킷의 실제 데이터를 나타냄, 
        //'%02c'는 각 바이트를 2자리의 16진수로 출력하는 형식 지정자
    }
    printf("\n\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE]; //오류 메시지를 저장하는 문자열, 
    //'PCAP_ERRBUF_SIZE'는 libpcap에서 제공하는 오류 메시지의 최대 길이를 나타냄

    pcap_if_t *dev_list; //네트워크 디바이스의 목록을 나타내는 구조체, 
    //'dev_list'는 네트워크 디바이스 목록에 대한 포인터

    char *dev; //선택된 네트워크 디바이스의 이름을 가리키는 포인터

    //'pcap_findalldevs' 함수는 사용 가능한 모든 네트워크 디바이스를 찾음,
    //만약 에러가 발생하면 '-1'을 리턴하고 'errbuf'에 오류 메시지를 저장함
    if (pcap_findalldevs(&dev_list, errbuf) == -1) { 
        printf("네트워크 디바이스를 찾을 수 없습니다. 오류: %s\n", errbuf);
        return 1;
    }

    dev = dev_list->name; // 첫 번쨰로 찾은 네트워크 디바이스의 이름을 'dev'에 저장힘

    //'pcap+ipen_live'함수를 사용하여 패킷 캡처 핸들을 연다
    //'dev'는 캡처할 네트워크 디바이스의 이름
    //'BUFSIZ'는 패킷을 저장할 버퍼의 크기
    //'1'은 promiscuous모드를 나타냄(1로 설정하면 모든 패킷을 캡처함)
    //'1000'은 타임아웃 시간을 나타냄(1000ms, 즉 1초)
    //함수가 성공하면 패킷 핸들러의 포인터를 반환하고, 실패하면 'NULL'을 반환하고 'errbuf'에 오류 메시지를 저장함
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    // 패킷 핸들러를 열 수 없는 경우, 오류 메시지와 함께 프로그램을 종료함
    if (handle == NULL) {
        printf("패킷 캡처 핸들러를 열 수 없습니다. 오류: %s\n", errbuf);
        return 1;
    }
    
    //'pcap_loop' 함수를 사용하여 패킷을 계속해서 캡처하고 처리함
    //'handle'은 패킷 핸들러
    //'0'은 패킷을 무한정 캡처하라는 의미
    //'packet_handler' 함수를 호출하여 각 패킷을 처리함
    pcap_loop(handle, 0, packet_handler, NULL);

    //패킷 핸들러를 닫음
    pcap_close(handle);

    return 0;
}
