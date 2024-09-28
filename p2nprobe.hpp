// Program created by student VUT FIT
// Name: Malashchuk Vladyslav
// Login: xmalas04
// Year: 2024
// PCAP NetFlow v5 exporter
// p2nprobe.hpp
#include <iostream>
#include <pcap.h>
#include <getopt.h>
#include <string.h>
#include <vector>
#include <math.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
using namespace std;

#define DEFAULT_TIMEOUT 60
#define SIZE_ETHERNET   14
#define SIZE_NF_HEADER   24
#define SIZE_NF_RECORD   48
//#define PCAP_ERRBUF_SIZE (256)
#define PACKET_SIZE 1464


/* Record Flow Structure */
typedef struct FlowRecord
{
	uint32_t srcaddr;      // 0 - 4 bytes: Source IP address
	uint32_t dstaddr;      // 4 - 8 bytes: Destination IP address
	uint32_t nexthop;      // 8 - 12 bytes: Next hop IP address
	uint16_t input;        // 12 - 14 bytes: Input interface index
	uint16_t output;       // 14 - 16 bytes: Output interface index
	uint32_t dPkts;        // 16 - 20 bytes: Total packets in flow
	uint32_t dOctets;      // 20 - 24 bytes: Total bytes in flow
	uint32_t First;        // 24 - 28 bytes: First packet timestamp (seconds)
	uint32_t Last;         // 28 - 32 bytes: Last packet timestamp (seconds)
	uint16_t srcport;      // 32 - 34 bytes: Source port number
	uint16_t dstport;      // 34 - 36 bytes: Destination port number
	uint8_t pad1;          // 36 - 37 bytes: Padding (1 byte)
	uint8_t tcp_flags;     // 37 - 38 bytes: TCP flags (1 byte)
	uint8_t prot;          // 38 - 39 bytes: IP protocol (1 byte)
	uint8_t tos;           // 39 - 40 bytes: Type of service (1 byte)
	uint16_t src_as;       // 40 - 42 bytes: Source AS (Autonomous System)
	uint16_t dst_as;       // 42 - 44 bytes: Destination AS (Autonomous System)
	uint8_t src_mask;      // 44 - 45 bytes: Source address mask (1 byte)
	uint8_t dst_mask;      // 45 - 46 bytes: Destination address mask (1 byte)
	uint16_t pad2;         // 46 - 48 bytes: Padding (2 bytes)
} record_flow;

/* Header Flow Structure */
typedef struct header_flow
{
	uint16_t version;          // 0 - 2 bytes: Version of the flow format
	uint16_t count;            // 2 - 4 bytes: Number of flows in this packet
	uint32_t SysUptime;        // 4 - 8 bytes: System uptime in milliseconds
	uint32_t unix_secs;        // 8 - 12 bytes: Unix time (seconds)
	uint32_t unix_nsecs;       // 12 - 16 bytes: Unix time (nanoseconds)
	uint32_t flow_sequence;    // 16 - 20 bytes: Sequence number of flow records
	uint8_t engine_type;       // 20 - 21 bytes: Type of flow-exporting engine
	uint8_t engine_id;         // 21 - 22 bytes: ID of the flow-exporting engine
	uint16_t sampling_interval; // 22 - 24 bytes: Sampling interval (in seconds)
} header_flow;

/// @brief Display Help
/// @param prog_name Name of Program
void display_usage(const char* prog_name);

/// @brief Packet handler function for processing and exporting NetFlow records
/// @param args Additional arguments (unused in this context)
/// @param header PCAP packet header containing timestamp and packet information
/// @param packet Captured packet data
/// 
/// This function processes network packets captured by PCAP, calculates the system uptime,
/// updates the flow cache, and exports flow records to a NetFlow collector. If the flow cache 
/// contains data, the function sends NetFlow packets to the collector and updates the sequence 
/// number of the exported flows. It also keeps track of the last packet's timestamp for future use.
/// 
/// @note This function should be used in conjunction with pcap_loop, as shown:
/// @code
/// if (pcap_loop(handle, -1, packet_handler, NULL) == -1)
/// {
///     cerr << "pcap_loop() Error";
///     return EXIT_FAILURE;
/// }
/// @endcode
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void flow_cache_loop(const u_char *packet, time_t sysuptime, vector<record_flow> *flow_export);
void send_netflow_packets(const struct timeval tv, time_t sysuptime, vector<record_flow> *flow_export);
void record_net_byte_order(record_flow *rec);
int fill_buffer_flows(vector<record_flow> *flow_export, int number, u_char *buffer);
void fill_buffer_header(const struct timeval tv, time_t sysuptime, int flows_count, u_char *b);