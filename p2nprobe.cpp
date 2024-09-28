// Program created by student VUT FIT
// Name: Malashchuk Vladyslav
// Login: xmalas04
// Year: 2024
// PCAP NetFlow v5 exporter
// p2nprobe.cpp

#include "p2nprobe.hpp"

/*****************************GLOBAL***************************************/

// Timer variables for active and inactive states (in milliseconds)
double activeTimerMilliseconds, inactiveTimerMilliseconds;

// Variables to store system boot time in seconds and microseconds
time_t systemBootTimeSec;		// System boot time in seconds
suseconds_t systemBootTimeUsec; // System boot time in microseconds
bool isBootTimeSet = false;		// Flag to check if boot time is set

// Cache to store flow records
vector<record_flow> flowCache; // Vector to hold cached flow records

int flowSequence = 0; // Sequence number for flows

// Timekeeping for the last packet received
struct timeval lastPacketTime; // Structure to hold the last packet's timestamp
time_t lastSysUptime;		   // Variable to track the last system uptime

// Socket variables for network communication
int socketDescriptor;			  // Socket file descriptor for communication
struct sockaddr_in serverAddress; // Structure to define the server address
struct hostent *serverEntry;	  // Pointer to hold information about the server host

/*****************************END***************************************/

/***************HELPER FUNCTIONS***************/

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

/*****************************END***************************************/

/*****************************ALL USED FUNCTIONS***************************************/

void handlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	// Set the system boot time if it's not already set
	if (!isBootTimeSet)
	{
		systemBootTimeSec = header->ts.tv_sec;
		systemBootTimeUsec = header->ts.tv_usec;
		isBootTimeSet = true;
	}

	// Calculate system uptime in milliseconds
	time_t sysuptime = (header->ts.tv_sec - systemBootTimeSec) * (double)1000 + round((header->ts.tv_usec - systemBootTimeUsec) / (double)1000);

	vector<record_flow> flow_export; // Container for exporting flow records
	int flows_count;				 // Number of flows processed

	// Process the flow cache based on the current packet and system uptime
	processFlowCache(packet, sysuptime, &flow_export);
	flows_count = flow_export.size(); // Get the count of processed flows

	// If there are flows to export, send them to the collector
	if (flows_count != 0)
	{
		exportNetFlowPackets(header->ts, sysuptime, &flow_export);
		flowSequence += flows_count; // Update the total flow sequence count
	}

	// Update the last packet timestamp and system uptime
	lastPacketTime.tv_sec = header->ts.tv_sec;
	lastPacketTime.tv_usec = header->ts.tv_usec;
	lastSysUptime = sysuptime;
}

void processFlowCache(const u_char *packet, time_t sysuptime, vector<record_flow> *flow_export)
{
	vector<record_flow>::iterator it; // Iterator for flow cache
	record_flow record;				  // Temporary flow record
	bool added = false;				  // Flag to check if a flow was added
	bool instant_export = false;	  // Flag for immediate export of flow

	// Extract IP header from the packet
	const struct ip *my_ip = (struct ip *)(packet + SIZE_ETHERNET);

	uint16_t sport = 0, dport = 0; // Source and destination ports
	uint8_t tcp_flags_packet = 0;  // TCP flags from the packet

	// Extract TCP header
	const struct tcphdr *my_tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + my_ip->ip_hl * 4);
	sport = my_tcp->th_sport;			 // Get source port
	dport = my_tcp->th_dport;			 // Get destination port
	tcp_flags_packet = my_tcp->th_flags; // Get TCP flags

	// Check for FIN or RST flags to determine if the flow should be instantly exported
	if (tcp_flags_packet & TH_FIN || tcp_flags_packet & TH_RST)
		instant_export = true;

	time_t active_time, inactive_time; // Variables for active and inactive flow time
	// Iterate through flow cache to update or add flows
	for (it = flowCache.begin(); it != flowCache.end(); ++it)
	{
		active_time = sysuptime - (*it).First;	// Calculate active time of the flow
		inactive_time = sysuptime - (*it).Last; // Calculate inactive time of the flow

		// Check if the flow is still active
		if (active_time < activeTimerMilliseconds && inactive_time < inactiveTimerMilliseconds)
		{
			// Check if the current packet matches an existing flow in the cache
			if (my_ip->ip_src.s_addr == (*it).srcaddr && my_ip->ip_dst.s_addr == (*it).dstaddr &&
				sport == (*it).srcport && dport == (*it).dstport && my_ip->ip_p == (*it).prot &&
				my_ip->ip_tos == (*it).tos)
			{
				added = true; // Mark that a flow was found

				// Update flow statistics
				(*it).dPkts++;
				(*it).dOctets += ntohs(my_ip->ip_len);
				(*it).Last = sysuptime;								  // Update last seen time
				(*it).tcp_flags = (*it).tcp_flags | tcp_flags_packet; // Update TCP flags

				// If instant export is required, prepare the flow for export
				if (instant_export)
				{
					flow_export->push_back(*it);
					flowCache.erase(it); // Remove the flow from cache
					it--;				 // Adjust iterator after erasing
				}
			}
		}
		else // Flow is inactive or expired
		{
			flow_export->push_back(*it); // Export the flow
			flowCache.erase(it);		 // Remove it from cache
			it--;						 // Adjust iterator after erasing
		}
	}

	// If no existing flow matched, create a new flow record
	if (!added)
	{
		// Create a new flow record
		record = {my_ip->ip_src.s_addr, my_ip->ip_dst.s_addr, 0, 0, 0, 1, ntohs(my_ip->ip_len),
				  (uint32_t)sysuptime, (uint32_t)sysuptime, sport, dport, 0,
				  tcp_flags_packet, my_ip->ip_p, my_ip->ip_tos, 0, 0, 0, 0, 0};

		flowCache.push_back(record); // Add the new flow to the cache

		// If instant export is required, prepare the flow for export
		if (instant_export)
		{
			it = flowCache.end();		 // Get iterator to the end
			it--;						 // Move back to the newly added flow
			flow_export->push_back(*it); // Add to export
			flowCache.erase(it);		 // Remove from cache
			it--;						 // Adjust iterator after erasing
		}
	}
}

void populateHeaderBuffer(const struct timeval tv, time_t sysuptime, int flows_count, u_char *buffer)
{
	header_flow *headerf = (header_flow *)(buffer); // Pointer to the header structure

	// Populate header fields
	*headerf = {htons(5), htons(flows_count), htonl(sysuptime), htonl(tv.tv_sec),
				htonl(tv.tv_usec * 1000), htonl(flowSequence), 0, 0, 0};
}

// Function to populate the flow buffer for export
int populateFlowBuffer(vector<record_flow> *flow_export, int number, u_char *buffer)
{
	int counter = 0; // Count of flows populated

	// Iterate through the flow records to populate the buffer
	for (auto it = flow_export->begin(); it != flow_export->end() && counter != number; ++it)
	{
		convertNetFlowToHostOrder(&*it);								 // Convert flow record to host order
		memcpy(buffer + counter * SIZE_NF_RECORD, &*it, SIZE_NF_RECORD); // Copy record to buffer

		flow_export->erase(it); // Remove the record from export list
		it--;					// Adjust iterator after erasing
		counter++;				// Increment counter
	}

	return counter; // Return the number of flows populated
}

// Function to convert flow record fields to host byte order
void convertNetFlowToHostOrder(record_flow *rec)
{
	rec->dPkts = htonl(rec->dPkts);
	rec->dOctets = htonl(rec->dOctets);
	rec->First = htonl(rec->First);
	rec->Last = htonl(rec->Last);
}

// Function to export NetFlow packets to the collector
void exportNetFlowPackets(const struct timeval tv, time_t sysuptime, vector<record_flow> *flow_export)
{
	int flows_count = flow_export->size(); // Get the number of flows to export
	u_char buffer[PACKET_SIZE];			   // Buffer for the packet

	// While there are flows left to export
	while (flows_count > 0)
	{
		int number = std::min(flows_count, 30);							  // Determine how many flows to send in this batch
		populateHeaderBuffer(tv, sysuptime, number, buffer);			  // Populate the header
		populateFlowBuffer(flow_export, number, buffer + SIZE_NF_HEADER); // Populate the flow records

		// Send the packet to the collector
		sendto(socketDescriptor, buffer, SIZE_NF_HEADER + number * SIZE_NF_RECORD, 0, (struct sockaddr *)&serverAddress, sizeof(serverAddress));
		flows_count -= number; // Reduce the remaining flows count
	}
}

/*****************************END***************************************/

/*****************************MAIN***************************************/

int main(int argc, char *argv[])
{
    // Check for valid argument count
    if (argc < 3 || argc > 7)
    {
        printUsage(argv[0]); // Print usage information
        return handleError("Args count isn't correct!");
    }

    string collector = argv[1]; // The first argument is the collector (host:port)
    string pcap_file = argv[2]; // The second argument is the PCAP file

    activeTimerMilliseconds = DEFAULT_ACTIVE_TIMEOUT; // Set default active timeout
    inactiveTimerMilliseconds = DEFAULT_INACTIVE_TIMEOUT; // Set default inactive timeout

    // Parse optional -a (active timeout) and -i (inactive timeout) parameters
    int opt;
    while ((opt = getopt(argc, argv, "a:i:")) != -1)
    {
        switch (opt)
        {
        case 'a': // Active timeout option
            try
            {
                activeTimerMilliseconds = atof(optarg) * 1000; // Convert to milliseconds
            }
            catch (const invalid_argument &)
            {
                printUsage(argv[0]); // Print usage if conversion fails
                return handleError("Invalid active timeout value.\n");
            }
            break;
        case 'i': // Inactive timeout option
            try
            {
                inactiveTimerMilliseconds = atof(optarg) * 1000; // Convert to milliseconds
            }
            catch (const invalid_argument &)
            {
                printUsage(argv[0]); // Print usage if conversion fails
                return handleError("Invalid inactive timeout value.\n");
            }
            break;
        default: // If an unknown option is provided
            printUsage(argv[0]); // Print usage information
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
        printUsage(argv[0]); // Print usage if format is invalid
        return handleError("Invalid collector format. Use <host>:<port>.\n");
    }

    string host = collector.substr(0, colon_pos); // Extract host
    int port = stoi(collector.substr(colon_pos + 1)); // Extract port

    // Open the PCAP file for reading
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file.c_str(), errbuf);
    if (handle == nullptr) // Check if the file opened successfully
        return handleError("Failed to open PCAP file");

    memset(&serverAddress, 0, sizeof(serverAddress)); // Initialize server address structure
    serverAddress.sin_family = AF_INET; // Set address family to IPv4

    // Resolve host to IP address
    if ((serverEntry = gethostbyname(host.c_str())) == NULL)
        return handleError("gethostbyname() failed");

    memcpy(&serverAddress.sin_addr, serverEntry->h_addr, serverEntry->h_length); // Copy address

    serverAddress.sin_port = htons(port); // Set port in network byte order

    // Create a UDP socket
    if ((socketDescriptor = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        return handleError("socket() failed");

    struct bpf_program fp; // Structure for the compiled filter

    // Compile the filter for capturing only TCP packets
    if (pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) == -1)
        return handleError("pcap_compile() Error");

    // Set the compiled filter to the packet capture handle
    if (pcap_setfilter(handle, &fp) == -1)
        return handleError("pcap_setfilter() Error");

    // Process packets in an infinite loop, calling handlePacket for each packet
    if (pcap_loop(handle, -1, handlePacket, NULL) == -1)
        return handleError("pcap_loop() Error");

    pcap_freecode(&fp); // Free the compiled filter
    pcap_close(handle); // Close the PCAP file

    // Export remaining flows in the cache if any
    if (flowCache.size() > 0)
        exportNetFlowPackets(lastPacketTime, lastSysUptime, &flowCache);

    return EXIT_SUCCESS; // Exit successfully
}

/*****************************END***************************************/