// Program created by student VUT FIT
// Name: Malashchuk Vladyslav
// Login: xmalas04
// Year: 2024
// PCAP NetFlow v5 exporter
// p2nprobe.cpp

#include "p2nprobe.hpp"

double activeTimerMilliseconds, inactiveTimerMilliseconds;

time_t systemBootTimeSec;
suseconds_t systemBootTimeUsec;
bool isBootTimeSet = false;

vector<record_flow> flowCache;

int flowSequence = 0;

struct timeval lastPacketTime;
time_t lastSysUptime;

int socketDescriptor;
struct sockaddr_in serverAddress;
struct hostent *serverEntry;

void printUsage(const char *prog_name)
{
	cerr << "Usage: " << prog_name << " <host>:<port> <pcap_file_path> [-a <active_timeout>] [-i <inactive_timeout>]\n"
		 << "Parameters:\n"
		 << "  <pcap_file_path> - Path to the PCAP file to be processed\n"
		 << "  <host> - IP address or domain name of the collector\n"
		 << "  <port> - Port number of the collector\n"
		 << "  -a <active_timeout> - Active flow timeout in seconds (default: 60)\n"
		 << "  -i <inactive_timeout> - Inactive flow timeout in seconds (default: 60)\n";
}

int handleError(const string &message)
{
	cerr << message << endl;
	return EXIT_FAILURE;
}

void handlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	if (!isBootTimeSet)
	{
		systemBootTimeSec = header->ts.tv_sec;
		systemBootTimeUsec = header->ts.tv_usec;
		isBootTimeSet = true;
	}
	time_t sysuptime = (header->ts.tv_sec - systemBootTimeSec) * (double)1000 + round((header->ts.tv_usec - systemBootTimeUsec) / (double)1000); // SysUpTime calculation

	vector<record_flow> flow_export;
	int flows_count;

	processFlowCache(packet, sysuptime, &flow_export); // go through the flow cache and filling the vector with flows to export
	flows_count = flow_export.size();

	if (flows_count != 0)
	{
		exportNetFlowPackets(header->ts, sysuptime, &flow_export); // exporting flows sending netflow packets to a collector

		flowSequence += flows_count;
	}

	// Values for the residual export
	lastPacketTime.tv_sec = header->ts.tv_sec;
	lastPacketTime.tv_usec = header->ts.tv_usec;
	lastSysUptime = sysuptime;
}

void processFlowCache(const u_char *packet, time_t sysuptime, vector<record_flow> *flow_export)
{
	vector<record_flow>::iterator it;
	record_flow record;
	bool added = false;
	bool instant_export = false;

	const struct ip *my_ip = (struct ip *)(packet + SIZE_ETHERNET); // pointing to the beginning of IP header

	uint16_t sport = 0, dport = 0; // icmp packet
	uint8_t tcp_flags_packet = 0;

	const struct tcphdr *my_tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + my_ip->ip_hl * 4); // pointing to the beginning of TCP header
	sport = my_tcp->th_sport;
	dport = my_tcp->th_dport;

	tcp_flags_packet = my_tcp->th_flags;

	if (tcp_flags_packet & TH_FIN || tcp_flags_packet & TH_RST)
		instant_export = true;

	time_t active_time, inactive_time;
	for (it = flowCache.begin(); it != flowCache.end(); ++it)
	{
		active_time = sysuptime - (*it).First;
		inactive_time = sysuptime - (*it).Last;

		if (active_time < activeTimerMilliseconds && inactive_time < inactiveTimerMilliseconds)
		{
			if (my_ip->ip_src.s_addr == (*it).srcaddr && my_ip->ip_dst.s_addr == (*it).dstaddr && sport == (*it).srcport && dport == (*it).dstport && my_ip->ip_p == (*it).prot && my_ip->ip_tos == (*it).tos)
			{
				// cout << "add to the flow:" << endl;
				added = true;

				(*it).dPkts++;
				(*it).dOctets += ntohs(my_ip->ip_len);
				(*it).Last = sysuptime;
				(*it).tcp_flags = (*it).tcp_flags | tcp_flags_packet;

				if (instant_export)
				{
					flow_export->push_back(*it);
					flowCache.erase(it);
					it--;
				}
			}
		}
		else
		{
			// cout << "export the flow (timers)" << endl;
			flow_export->push_back(*it);
			flowCache.erase(it);
			it--;
		}
	}

	if (!added)
	{
		// cout << "add to the flow cache" << endl;
		record = {my_ip->ip_src.s_addr, my_ip->ip_dst.s_addr, 0, 0, 0, 1, ntohs(my_ip->ip_len), (uint32_t)sysuptime, (uint32_t)sysuptime, sport, dport, 0, tcp_flags_packet, my_ip->ip_p, my_ip->ip_tos, 0, 0, 0, 0, 0};

		flowCache.push_back(record);

		if (instant_export)
		{
			it = flowCache.end();
			it--;

			flow_export->push_back(*it);
			flowCache.erase(it);
			it--;
		}
	}
}

void populateHeaderBuffer(const struct timeval tv, time_t sysuptime, int flows_count, u_char *buffer)
{
	header_flow *headerf = (header_flow *)(buffer);

	*headerf = {htons(5), htons(flows_count), htonl(sysuptime), htonl(tv.tv_sec), htonl(tv.tv_usec * 1000), htonl(flowSequence), 0, 0, 0};
}

int populateFlowBuffer(vector<record_flow> *flow_export, int number, u_char *buffer)
{
	int counter = 0;

	for (auto it = flow_export->begin(); it != flow_export->end() && counter != number; ++it)
	{
		convertNetFlowToHostOrder(&*it);
		memcpy(buffer + counter * SIZE_NF_RECORD, &*it, SIZE_NF_RECORD);

		flow_export->erase(it);
		it--;
		counter++;
	}

	return counter;
}

void convertNetFlowToHostOrder(record_flow *rec)
{
	rec->dPkts = htonl(rec->dPkts);
	rec->dOctets = htonl(rec->dOctets);
	rec->First = htonl(rec->First);
	rec->Last = htonl(rec->Last);
}

void exportNetFlowPackets(const struct timeval tv, time_t sysuptime, vector<record_flow> *flow_export)
{
	int flows_count = flow_export->size();
	u_char buffer[PACKET_SIZE];

	while (flows_count > 0)
	{
		int number = std::min(flows_count, 30);
		populateHeaderBuffer(tv, sysuptime, number, buffer);
		populateFlowBuffer(flow_export, number, buffer + SIZE_NF_HEADER);
		sendto(socketDescriptor, buffer, SIZE_NF_HEADER + number * SIZE_NF_RECORD, 0, (struct sockaddr *)&serverAddress, sizeof(serverAddress));
		flows_count -= number;
	}
}

/******************************/

int main(int argc, char *argv[])
{
	if (argc < 3 || argc > 7)
	{
		printUsage(argv[0]);
		return handleError("Args count isnt correct!");
	}

	string collector = argv[1]; // The first argument is the collector
	string pcap_file = argv[2]; // The second argument is the PCAP file
	activeTimerMilliseconds = DEFAULT_ACTIVE_TIMEOUT;
	inactiveTimerMilliseconds = DEFAULT_INACTIVE_TIMEOUT;
	// Parse optional -a and -i parameters
	int opt;
	while ((opt = getopt(argc, argv, "a:i:")) != -1)
	{
		switch (opt)
		{
		case 'a':
			try
			{
				activeTimerMilliseconds = atof(optarg) * 1000;
			}
			catch (const invalid_argument &)
			{
				printUsage(argv[0]);
				return handleError("Invalid active timeout value.\n");
			}
			break;
		case 'i':
			try
			{
				inactiveTimerMilliseconds = atof(optarg) * 1000;
			}
			catch (const invalid_argument &)
			{
				printUsage(argv[0]);
				return handleError("Invalid active timeout value.\n");
			}
			break;
		default:
			printUsage(argv[0]);
			return handleError("Some Error in args.");
		}
	}

	// Ensure the collector and pcap file are provided
	if (collector.empty() || pcap_file.empty())
	{
		printUsage(argv[0]);
		return handleError("Collector or Pcap not provided.");
	}

	// Split collector into host and port
	size_t colon_pos = collector.find(':');
	if (colon_pos == string::npos || colon_pos == 0 || colon_pos == collector.size() - 1)
	{
		printUsage(argv[0]);
		return handleError("Invalid collector format. Use <host>:<port>.\n");
	}

	string host = collector.substr(0, colon_pos);
	int port = stoi(collector.substr(colon_pos + 1));

	// Open the PCAP file for reading
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_offline(pcap_file.c_str(), errbuf);
	if (handle == nullptr)
		return handleError("Failed to open PCAP file");

	memset(&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;

	if ((serverEntry = gethostbyname(host.c_str())) == NULL)
		return handleError("gethostbyname() failed");

	memcpy(&serverAddress.sin_addr, serverEntry->h_addr, serverEntry->h_length);

	serverAddress.sin_port = htons(port);

	if ((socketDescriptor = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return handleError("socket() failed");

	struct bpf_program fp; // the compiled filter

	// compile the filter
	if (pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) == -1)
		return handleError("pcap_compile() Error");

	// set the filter to the packet capture handle
	if (pcap_setfilter(handle, &fp) == -1)
		return handleError("pcap_setfilter() Error");

	// packets are processed in turn by function mypcap_handler() in the infinite loop
	if (pcap_loop(handle, -1, handlePacket, NULL) == -1)
		return handleError("pcap_loop() Error");


	pcap_freecode(&fp); 
	pcap_close(handle);

	if (flowCache.size() > 0)
		exportNetFlowPackets(lastPacketTime, lastSysUptime, &flowCache);

	return EXIT_SUCCESS;
}
