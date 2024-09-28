// Program created by student VUT FIT
// Name: Malashchuk Vladyslav
// Login: xmalas04
// Year: 2024
// PCAP NetFlow v5 exporter
// p2nprobe.cpp

#include "p2nprobe.hpp"

double activeTimer_ms, inactiveTimer_ms;
int flow_maxCount;

time_t boot_time_sec;
suseconds_t boot_time_usec;
bool boot_time_set = false;

vector<record_flow> flow_cache;

int flow_seq = 0;

struct timeval tv_last; // timeval of the last packet
time_t sysuptime_last;	// sysuptime of the last packet

int sock;				   // socket descriptor
struct sockaddr_in server; // address structure of the server
struct hostent *servent;   // network host entry required by gethostbyname()

void display_usage(const char *prog_name)
{
	cerr << "Usage: " << prog_name << " <host>:<port> <pcap_file_path> [-a <active_timeout>] [-i <inactive_timeout>]\n"
		 << "Parameters:\n"
		 << "  <pcap_file_path> - Path to the PCAP file to be processed\n"
		 << "  <host> - IP address or domain name of the collector\n"
		 << "  <port> - Port number of the collector\n"
		 << "  -a <active_timeout> - Active flow timeout in seconds (default: 60)\n"
		 << "  -i <inactive_timeout> - Inactive flow timeout in seconds (default: 60)\n";
}

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	if (!boot_time_set)
	{
		boot_time_sec = header->ts.tv_sec;
		boot_time_usec = header->ts.tv_usec;
		boot_time_set = true;
	}
	time_t sysuptime = (header->ts.tv_sec - boot_time_sec) * (double)1000 + round((header->ts.tv_usec - boot_time_usec) / (double)1000); // SysUpTime calculation

	vector<record_flow> flow_export;
	int flows_count;

	flow_cache_loop(packet, sysuptime, &flow_export); // go through the flow cache and filling the vector with flows to export
	flows_count = flow_export.size();

	if (flows_count != 0)
	{
		send_netflow_packets(header->ts, sysuptime, &flow_export); // exporting flows sending netflow packets to a collector

		flow_seq += flows_count;
	}

	// Values for the residual export
	tv_last.tv_sec = header->ts.tv_sec;
	tv_last.tv_usec = header->ts.tv_usec;
	sysuptime_last = sysuptime;
}

void flow_cache_loop(const u_char *packet, time_t sysuptime, vector<record_flow> *flow_export)
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
	for (it = flow_cache.begin(); it != flow_cache.end(); ++it)
	{
		active_time = sysuptime - (*it).First;
		inactive_time = sysuptime - (*it).Last;

		if (active_time < activeTimer_ms && inactive_time < inactiveTimer_ms)
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
					flow_cache.erase(it);
					it--;
				}
			}
		}
		else
		{
			// cout << "export the flow (timers)" << endl;
			flow_export->push_back(*it);
			flow_cache.erase(it);
			it--;
		}
	}

	if (!added)
	{
		// cout << "add to the flow cache" << endl;
		record = {my_ip->ip_src.s_addr, my_ip->ip_dst.s_addr, 0, 0, 0, 1, ntohs(my_ip->ip_len), (uint32_t)sysuptime, (uint32_t)sysuptime, sport, dport, 0, tcp_flags_packet, my_ip->ip_p, my_ip->ip_tos, 0, 0, 0, 0, 0};

		flow_cache.push_back(record);

		if (instant_export)
		{
			it = flow_cache.end();
			it--;

			flow_export->push_back(*it);
			flow_cache.erase(it);
			it--;
		}
	}

	/*if (int(flow_cache.size()) > flow_maxCount)
	{
		// cout << "export the oldest flow" << endl;
		it = flow_cache.begin();

		flow_export->push_back(*it);
		flow_cache.erase(it);
		it--;
	}*/
}

void fill_buffer_header(const struct timeval tv, time_t sysuptime, int flows_count, u_char *buffer)
{
	header_flow *headerf = (header_flow *)(buffer);

	*headerf = {htons(5), htons(flows_count), htonl(sysuptime), htonl(tv.tv_sec), htonl(tv.tv_usec * 1000), htonl(flow_seq), 0, 0, 0};
}

int fill_buffer_flows(vector<record_flow> *flow_export, int number, u_char *buffer)
{
	int counter = 0;

	for (auto it = flow_export->begin(); it != flow_export->end() && counter != number; ++it)
	{
		record_net_byte_order(&*it);
		memcpy(buffer + counter * SIZE_NF_RECORD, &*it, SIZE_NF_RECORD);

		flow_export->erase(it);
		it--;
		counter++;
	}

	return counter;
}

void record_net_byte_order(record_flow *rec)
{
	rec->dPkts = htonl(rec->dPkts);
	rec->dOctets = htonl(rec->dOctets);
	rec->First = htonl(rec->First);
	rec->Last = htonl(rec->Last);
}

void send_netflow_packets(const struct timeval tv, time_t sysuptime, vector<record_flow> *flow_export)
{
	int flows_count = flow_export->size();
	int number;
	u_char buffer[PACKET_SIZE];
	while (flows_count > 0)
	{
		int number = std::min(flows_count, 30);
		fill_buffer_header(tv, sysuptime, number, buffer);
		fill_buffer_flows(flow_export, number, buffer + SIZE_NF_HEADER);
		sendto(sock, buffer, SIZE_NF_HEADER + number * SIZE_NF_RECORD, 0, (struct sockaddr *)&server, sizeof(server));
		flows_count -= number;
	}
}

/******************************/

int main(int argc, char *argv[])
{
	if (argc < 3 || argc > 7)
	{
		display_usage(argv[0]);
		return EXIT_FAILURE;
	}

	string collector = argv[1]; // The first argument is the collector
	string pcap_file = argv[2]; // The second argument is the PCAP file
	int active_timeout = DEFAULT_TIMEOUT;
	int inactive_timeout = DEFAULT_TIMEOUT;

	// Parse optional -a and -i parameters
	int opt;
	while ((opt = getopt(argc, argv, "a:i:")) != -1)
	{
		switch (opt)
		{
		case 'a':
			try
			{
				active_timeout = stoi(optarg);
				activeTimer_ms = atof(optarg) * 1000;
			}
			catch (const invalid_argument &)
			{
				cerr << "Invalid active timeout value.\n";
				display_usage(argv[0]);
				return EXIT_FAILURE;
			}
			break;
		case 'i':
			try
			{
				inactive_timeout = stoi(optarg);
				inactiveTimer_ms = atof(optarg) * 1000;
			}
			catch (const invalid_argument &)
			{
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
	if (collector.empty() || pcap_file.empty())
	{
		display_usage(argv[0]);
		return EXIT_FAILURE;
	}

	// Split collector into host and port
	size_t colon_pos = collector.find(':');
	if (colon_pos == string::npos || colon_pos == 0 || colon_pos == collector.size() - 1)
	{
		cerr << "Invalid collector format. Use <host>:<port>.\n";
		display_usage(argv[0]);
		return EXIT_FAILURE;
	}

	string host = collector.substr(0, colon_pos);
	int port = stoi(collector.substr(colon_pos + 1));

	// Open the PCAP file for reading
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_offline(pcap_file.c_str(), errbuf);
	if (handle == nullptr)
	{
		cerr << "Failed to open PCAP file: " << errbuf << endl;
		return EXIT_FAILURE;
	}

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;

	if ((servent = gethostbyname(host.c_str())) == NULL)
	{
		cerr << "gethostbyname() failed" << endl;
		return EXIT_FAILURE;
	}

	memcpy(&server.sin_addr, servent->h_addr, servent->h_length);

	server.sin_port = htons(port);

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		cerr << "socket() failed" << endl;
		return EXIT_FAILURE;
	}

	struct pcap_pkthdr *header;
	struct bpf_program fp; // the compiled filter

	// compile the filter
	if (pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) == -1)
	{
		cerr << "pcap_compile() Error";
		return EXIT_FAILURE;
	}

	// set the filter to the packet capture handle
	if (pcap_setfilter(handle, &fp) == -1)
	{
		cerr << "pcap_setfilter() Error";
		return EXIT_FAILURE;
	}

	// packets are processed in turn by function mypcap_handler() in the infinite loop
	if (pcap_loop(handle, -1, mypcap_handler, NULL) == -1)
	{
		cerr << "pcap_loop() Error";
		return EXIT_FAILURE;
	}

	pcap_close(handle);

	/*
	 * Exporting remaining flows in the flow cache.
	 */
	int residue_size = flow_cache.size();

	if (residue_size > 0)
		send_netflow_packets(tv_last, sysuptime_last, &flow_cache);
	return EXIT_SUCCESS;
}
