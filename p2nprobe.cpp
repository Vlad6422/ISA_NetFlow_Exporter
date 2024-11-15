// Program created by student VUT FIT
// Name: Malashchuk Vladyslav
// Login: xmalas04
// Year: 2024
// PCAP NetFlow v5 exporter
// p2nprobe.cpp

#include "p2nprobe.hpp"

/*****************************GLOBAL***************************************/
vector<record_flow> flowRecords;
// Timer variables for active and inactive states (in milliseconds)
double activeTimerMilliseconds, inactiveTimerMilliseconds;

// Variables to store system boot time in seconds and microseconds
time_t systemBootTimeSec;       // System boot time in seconds
suseconds_t systemBootTimeUsec; // System boot time in microseconds
bool isBootTimeSet = false;     // Flag to check if boot time is set

// Cache to store flow records
vector<record_flow> flowCache; // Vector to hold cached flow records

int flowSequence = 0; // Sequence number for flows

// Timekeeping for the last packet received
struct timeval lastPacketTime; // Structure to hold the last packet's timestamp
time_t lastSysUptime;          // Variable to track the last system uptime

// Socket variables for network communication
int socketDescriptor;             // Socket file descriptor for communication
struct sockaddr_in serverAddress; // Structure to define the server address
struct hostent *serverEntry;      // Pointer to hold information about the server host

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
// Function to set system boot time if not already set
void setSystemBootTime(const struct timeval &packetTimestamp)
{
    if (!isBootTimeSet)
    {
        systemBootTimeSec = packetTimestamp.tv_sec;
        systemBootTimeUsec = packetTimestamp.tv_usec;
        isBootTimeSet = true;
    }
}

// Function to calculate system uptime in milliseconds
time_t calculateSystemUptime(const struct timeval &packetTimestamp)
{
    return (packetTimestamp.tv_sec - systemBootTimeSec) * (double)1000 +
           round((packetTimestamp.tv_usec - systemBootTimeUsec) / (double)1000);
}

// Function to process and export flow records if any are present
void processAndExportFlows(const u_char *packet, time_t sysUptime, const struct timeval &packetTimestamp)
{
    processFlowCache(packet, sysUptime, &flowRecords); // Process the flow cache

    int flowCount = flowRecords.size();
    if (flowCount > 29)
    {

        exportNetFlowPackets(packetTimestamp, sysUptime, &flowRecords); // Export the flow records
        flowSequence += flowCount;                                      // Update the flow sequence count
    }
}
// Function to check if the packet matches an existing flow
bool matchFlow(const struct ip *my_ip, const struct tcphdr *my_tcp, vector<record_flow>::iterator &flowIterator)
{
    return (my_ip->ip_src.s_addr == flowIterator->srcaddr &&
            my_ip->ip_dst.s_addr == flowIterator->dstaddr &&
            my_tcp->th_sport == flowIterator->srcport &&
            my_tcp->th_dport == flowIterator->dstport &&
            my_ip->ip_p == flowIterator->prot &&
            my_ip->ip_tos == flowIterator->tos);
}

// Function to update an existing flow record with the packet data
void updateFlow(vector<record_flow>::iterator &flowIterator, const struct ip *my_ip, const struct tcphdr *my_tcp, time_t sysuptime, bool shouldExportNow, vector<record_flow> *flow_export)
{
    flowIterator->dPkts++;                         // Increment packet count
    flowIterator->dOctets += ntohs(my_ip->ip_len); // Increment byte count
    flowIterator->Last = sysuptime;                // Update last seen time
    flowIterator->tcp_flags |= my_tcp->th_flags;   // Update TCP flags

    // Export the flow if necessary
    if (shouldExportNow)
    {
        flow_export->push_back(*flowIterator); // Push flow to export buffer
        flowCache.erase(flowIterator);         // Remove from cache
        flowIterator--;                        // Adjust iterator after erasing
    }
}

// Function to create a new flow record
void createNewFlow(const struct ip *my_ip, const struct tcphdr *my_tcp, time_t sysuptime, vector<record_flow> *flow_export, bool shouldExportNow)
{
    record_flow newFlow = {
        my_ip->ip_src.s_addr, my_ip->ip_dst.s_addr, 0, 0, 0, 1, ntohs(my_ip->ip_len),
        (uint32_t)sysuptime, (uint32_t)sysuptime, my_tcp->th_sport, my_tcp->th_dport, 0,
        my_tcp->th_flags, my_ip->ip_p, my_ip->ip_tos, 0, 0, 0, 0, 0};

    flowCache.push_back(newFlow); // Add the new flow to the cache

    // Export the new flow if necessary
    if (shouldExportNow)
    {
        auto flowIterator = flowCache.end();
        flowIterator--;
        flow_export->push_back(*flowIterator); // Add to export
        flowCache.erase(flowIterator);         // Remove from cache
        flowIterator--;
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
        convertNetFlowToHostOrder(&*it);                                 // Convert flow record to host order
        memcpy(buffer + counter * SIZE_NF_RECORD, &*it, SIZE_NF_RECORD); // Copy record to buffer

        flow_export->erase(it); // Remove the record from export list
        it--;                   // Adjust iterator after erasing
        counter++;              // Increment counter
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

/*****************************END***************************************/

/*****************************ALL USED FUNCTIONS***************************************/

// Main packet handler function
void handlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // Set system boot time if not already set
    setSystemBootTime(header->ts);

    // Calculate system uptime in milliseconds
    time_t sysUptime = calculateSystemUptime(header->ts);
    // Process flows and export if necessary
    processAndExportFlows(packet, sysUptime, header->ts);

    // Update the last packet timestamp and system uptime
    lastPacketTime.tv_sec = header->ts.tv_sec;
    lastPacketTime.tv_usec = header->ts.tv_usec;
    lastSysUptime = sysUptime;
}

// Function to process an incoming packet
void processFlowCache(const u_char *packet, time_t sysuptime, vector<record_flow> *flow_export)
{
    // Extract IP and TCP headers from the packet
    const struct ip *my_ip = (struct ip *)(packet + SIZE_ETHERNET);
    const struct tcphdr *my_tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + my_ip->ip_hl * 4);
    vector<record_flow>::iterator flowIterator; // Iterator for flow cache
    bool isFlowAdded = false;                   // Flag to check if a flow was added
    bool shouldExportNow = false;               // Flag for immediate export of flow
    uint8_t tcpFlags = my_tcp->th_flags;

    // If FIN or RST flag is set, mark for immediate export
    if (tcpFlags & TH_FIN || tcpFlags & TH_RST)
        shouldExportNow = true;

    time_t active_time, inactive_time; // Active and inactive time for flow validation

    // Iterate through flow cache to update or add flows
    for (flowIterator = flowCache.begin(); flowIterator != flowCache.end(); ++flowIterator)
    {
        active_time = sysuptime - flowIterator->First;  // Calculate active time of the flow
        inactive_time = sysuptime - flowIterator->Last; // Calculate inactive time of the flow

        // If flow is still active, check if packet matches
        if (active_time < activeTimerMilliseconds && inactive_time < inactiveTimerMilliseconds)
        {
            if (matchFlow(my_ip, my_tcp, flowIterator))
            {
                isFlowAdded = true; // Flow matched

                updateFlow(flowIterator, my_ip, my_tcp, sysuptime, shouldExportNow, flow_export);
            }
        }
        else
        {                                          // Flow is inactive or expired
            flow_export->push_back(*flowIterator); // Export expired flow
            flowCache.erase(flowIterator);         // Remove from cache
            flowIterator--;                        // Adjust iterator
        }
    }

    // If no existing flow was found, create a new flow record
    if (!isFlowAdded)
    {
        createNewFlow(my_ip, my_tcp, sysuptime, flow_export, shouldExportNow);
    }
}

// Function to export NetFlow packets to the collector
void exportNetFlowPackets(const struct timeval tv, time_t sysuptime, vector<record_flow> *flow_export)
{
    int flows_count = flow_export->size(); // Get the number of flows to export
    u_char buffer[PACKET_SIZE];            // Buffer for the packet

    // While there are flows left to export
    while (flows_count > 0)
    {
        int number = std::min(flows_count, 30);                           // Determine how many flows to send in this batch
        populateHeaderBuffer(tv, sysuptime, number, buffer);              // Populate the header
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

    activeTimerMilliseconds = DEFAULT_ACTIVE_TIMEOUT * 1000;     // Set default active timeout
    inactiveTimerMilliseconds = DEFAULT_INACTIVE_TIMEOUT * 1000; // Set default inactive timeout

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
        default:                 // If an unknown option is provided
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

    string host = collector.substr(0, colon_pos);     // Extract host
    int port = stoi(collector.substr(colon_pos + 1)); // Extract port

    // Open the PCAP file for reading
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file.c_str(), errbuf);
    if (handle == nullptr) // Check if the file opened successfully
        return handleError("Failed to open PCAP file");

    memset(&serverAddress, 0, sizeof(serverAddress)); // Initialize server address structure
    serverAddress.sin_family = AF_INET;               // Set address family to IPv4

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
    {
        cout<<flowRecords.size();
        flowCache.insert(flowCache.end(), flowRecords.begin(), flowRecords.end());
        exportNetFlowPackets(lastPacketTime, lastSysUptime, &flowCache);
    }
    return EXIT_SUCCESS; // Exit successfully
}

/*****************************END***************************************/