// Program created by student VUT FIT
// Name: Malashchuk Vladyslav
// Login: xmalas04
// Year: 2024
// PCAP NetFlow v5 exporter
// p2nprobe.cpp
#include "p2nprobe.hpp" 
/* Global variables */
double activeTimer_ms, inactiveTimer_ms; int flow_maxCount;

time_t boot_time_sec; suseconds_t boot_time_usec; bool boot_time_set = false;

vector<record_flow> flow_cache;

int flow_seq = 0;

struct timeval tv_last; // timeval of the last packet
time_t sysuptime_last; // sysuptime of the last packet

int sock;                        // socket descriptor
struct sockaddr_in server;		 // address structure of the server
struct hostent *servent;         // network host entry required by gethostbyname()  
void sendNetFlowPacket(int sock, struct sockaddr_in server) {
    u_char buffer[1488];  // Maximum size for a single UDP packet
    memset(buffer, 0, sizeof(buffer));

    // NetFlow v5 Header
    int offset = 0;

    // Version (2 bytes)
    uint16_t version = htons(5);  // NetFlow version 5
    memcpy(&buffer[offset], &version, sizeof(version));
    offset += 2;

    // Count (2 bytes) - number of flow records
    uint16_t count = htons(1); // 1 flow record
    memcpy(&buffer[offset], &count, sizeof(count));
    offset += 2;

    // System uptime (4 bytes)
    uint32_t uptime = htonl(0);  // Placeholder for uptime
    memcpy(&buffer[offset], &uptime, sizeof(uptime));
    offset += 4;

    // Unix timestamp (4 bytes)
    uint32_t timestamp = htonl(static_cast<uint32_t>(time(NULL)));  // Current time
    memcpy(&buffer[offset], &timestamp, sizeof(timestamp));
    offset += 4;
    // Unix timestamp (4 bytes)
    uint32_t timestamp2 = htonl(static_cast<uint32_t>(time(NULL)));  // Current time
    memcpy(&buffer[offset], &timestamp2, sizeof(timestamp2));
    offset += 4;

    // Sequence number (4 bytes)
    uint32_t sequence = htonl(0); // Placeholder for sequence number
    memcpy(&buffer[offset], &sequence, sizeof(sequence));
    offset += 4;

    // Source ID (4 bytes)
    uint32_t sourceID = htonl(0); // Placeholder for source ID
    memcpy(&buffer[offset], &sourceID, sizeof(sourceID));
    offset += 4;

    // Flow Record (for 1 flow) - should be exactly 48 bytes
    // Ensure we fill this section properly

    // Src IP (4 bytes)
    struct in_addr srcIP;
    inet_pton(AF_INET, "192.168.1.1", &srcIP);
    memcpy(&buffer[offset], &srcIP, sizeof(srcIP));
    offset += 4;

    // Dst IP (4 bytes)
    struct in_addr dstIP;
    inet_pton(AF_INET, "192.168.1.2", &dstIP);
    memcpy(&buffer[offset], &dstIP, sizeof(dstIP));
    offset += 4;

    // Next Hop (4 bytes)
    struct in_addr nextHop;
    inet_pton(AF_INET, "192.168.1.254", &nextHop);
    memcpy(&buffer[offset], &nextHop, sizeof(nextHop));
    offset += 4;

    // Input Interface (2 bytes)
    uint16_t inputIF = htons(0); // Example input interface
    memcpy(&buffer[offset], &inputIF, sizeof(inputIF));
    offset += 2;

    // Output Interface (2 bytes)
    uint16_t outputIF = htons(0); // Example output interface
    memcpy(&buffer[offset], &outputIF, sizeof(outputIF));
    offset += 2;

    // Packet Count (4 bytes)
    uint32_t packetCount = htonl(10);  // Placeholder for packet count
    memcpy(&buffer[offset], &packetCount, sizeof(packetCount));
    offset += 4;

    // Byte Count (4 bytes)
    uint32_t byteCount = htonl(1500);  // Placeholder for byte count
    memcpy(&buffer[offset], &byteCount, sizeof(byteCount));
    offset += 4;

    // Start Time (4 bytes)
    uint32_t startTime = htonl(static_cast<uint32_t>(time(NULL)));  // Current time
    memcpy(&buffer[offset], &startTime, sizeof(startTime));
    offset += 4;

    // End Time (4 bytes)
    uint32_t endTime = htonl(static_cast<uint32_t>(time(NULL)));  // Current time
    memcpy(&buffer[offset], &endTime, sizeof(endTime));
    offset += 4;

    // Src Port (2 bytes)
    uint16_t srcPort = htons(12345);  // Placeholder source port
    memcpy(&buffer[offset], &srcPort, sizeof(srcPort));
    offset += 2;

    // Dst Port (2 bytes)
    uint16_t dstPort = htons(80);  // Placeholder destination port
    memcpy(&buffer[offset], &dstPort, sizeof(dstPort));
    offset += 2;
    
    buffer[offset++] = 0x00;  // Padding
    // TCP Flags (1 byte)
    buffer[offset++] = 0x00;  // No flags

    // Protocol (1 byte)
    buffer[offset++] = 0x06;  // TCP

    // TOS (1 byte)
    buffer[offset++] = 0x00;  // Type of Service

    // Src AS (2 bytes)
    uint16_t srcAS = htons(0);  // Placeholder for source AS
    memcpy(&buffer[offset], &srcAS, sizeof(srcAS));
    offset += 2;

    // Dst AS (2 bytes)
    uint16_t dstAS = htons(0);  // Placeholder for destination AS
    memcpy(&buffer[offset], &dstAS, sizeof(dstAS));
    offset += 2;

    // Src Mask (1 byte)
    buffer[offset++] = 0x00;  // Placeholder for source mask

    // Dst Mask (1 byte)
    buffer[offset++] = 0x00;  // Placeholder for destination mask

    // Pad (2 bytes)
    buffer[offset++] = 0x00;  // Padding
    buffer[offset++] = 0x00;  // Padding

    // Check if we have exactly 72 bytes (24 for header + 48 for flow record)
    if (offset != 72) {
        cerr << "Error: Packet size is incorrect: " << offset << " bytes" << endl;
        return;
    }

    // Send the NetFlow packet
    if (sendto(sock, buffer, offset, 0, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("sendto failed");
    }
}
void display_usage(const char* prog_name) {
    cerr << "Usage: " << prog_name << " <host>:<port> <pcap_file_path> [-a <active_timeout>] [-i <inactive_timeout>]\n"
              << "Parameters:\n"
              << "  <pcap_file_path> - Path to the PCAP file to be processed\n"
              << "  <host> - IP address or domain name of the collector\n"
              << "  <port> - Port number of the collector\n"
              << "  -a <active_timeout> - Active flow timeout in seconds (default: 60)\n"
              << "  -i <inactive_timeout> - Inactive flow timeout in seconds (default: 60)\n";
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

}




/******************************/


int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 7) {
        display_usage(argv[0]);
        return EXIT_FAILURE;
    }

    string collector = argv[1]; // The first argument is the collector
    string pcap_file = argv[2]; // The second argument is the PCAP file
    int active_timeout = DEFAULT_TIMEOUT;
    int inactive_timeout = DEFAULT_TIMEOUT;

    // Parse optional -a and -i parameters
    int opt;
    while ((opt = getopt(argc, argv, "a:i:")) != -1) {
        switch (opt) {
            case 'a':
                try {
                    active_timeout = stoi(optarg);
                } catch (const invalid_argument&) {
                    cerr << "Invalid active timeout value.\n";
                    display_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                break;
            case 'i':
                try {
                    inactive_timeout = stoi(optarg);
                } catch (const invalid_argument&) {
                    cerr << "Invalid inactive timeout value.\n";
                    display_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                break;
            default:
                display_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    // Ensure the collector and pcap file are provided
    if (collector.empty() || pcap_file.empty()) {
        display_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Split collector into host and port
    size_t colon_pos = collector.find(':');
    if (colon_pos == string::npos || colon_pos == 0 || colon_pos == collector.size() - 1) {
        cerr << "Invalid collector format. Use <host>:<port>.\n";
        display_usage(argv[0]);
        return EXIT_FAILURE;
    }

    string host = collector.substr(0, colon_pos);
    int port = stoi(collector.substr(colon_pos + 1));

    // Open the PCAP file for reading
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(pcap_file.c_str(), errbuf);
    if (handle == nullptr) {
        cerr << "Failed to open PCAP file: " << errbuf << endl;
        return EXIT_FAILURE;
    }

	memset(&server,0,sizeof(server));								
	server.sin_family = AF_INET;   

	if ((servent = gethostbyname(host.c_str())) == NULL){
        cerr <<"gethostbyname() failed"<<endl;
        return EXIT_FAILURE;
    }			
		

	memcpy(&server.sin_addr, servent->h_addr, servent->h_length);	

	server.sin_port = htons(port);


	if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1){
        cerr <<"socket() failed"<<endl;
        return EXIT_FAILURE;
    }			
		

    // Print collector information
    cout << "Collector host: " << host << "\n";
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &server.sin_addr, ip_str, sizeof(ip_str));
    cout << "Collector IP: " << ip_str << "\n";  
    cout << "Collector port: " << ntohs(server.sin_port) << "\n";  
    cout << "PCAP file: " << pcap_file << "\n";
    cout << "Active timeout: " << active_timeout << "\n";
    cout << "Inactive timeout: " << inactive_timeout << "\n";

     sendNetFlowPacket(sock, server);

    struct pcap_pkthdr* header;
    struct bpf_program fp;          	// the compiled filter
  
  	// compile the filter
  	if (pcap_compile(handle,&fp,"tcp",0,PCAP_NETMASK_UNKNOWN) == -1){
        cerr << "pcap_compile() Error";
        return EXIT_FAILURE;
    }
    	
  
  	// set the filter to the packet capture handle
  	if (pcap_setfilter(handle,&fp) == -1){
        cerr << "pcap_setfilter() Error";
        return EXIT_FAILURE;
    }
    	

  	// packets are processed in turn by function mypcap_handler() in the infinite loop
    if (pcap_loop(handle,-1,packet_handler,NULL) == -1){
        cerr << "pcap_loop() Error";
        return EXIT_FAILURE;
    }
    	

    pcap_close(handle);
    return EXIT_SUCCESS;
}
