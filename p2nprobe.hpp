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

// Default Values Of TIMEOUTs | From Lecture 10 - NetFlow | Slide 9/34 + 10/34
//#define DEFAULT_ACTIVE_TIMEOUT 30*60
//#define DEFAULT_INACTIVE_TIMEOUT 15
// From out Task
#define DEFAULT_ACTIVE_TIMEOUT 60
#define DEFAULT_INACTIVE_TIMEOUT 60

#define SIZE_ETHERNET   14 // Could Be 18 of 16 in WSL
#define SIZE_NF_HEADER   24
#define SIZE_NF_RECORD   48

///Maximum of 30 records per packet:
///Header Size: 24 bytes
///Records Size: 30 * SIZE_NF_RECORD (assuming SIZE_NF_RECORD is 48 bytes, this would be 30 * 48 = 1440 bytes)
///Total Size: 24 + 1440 = 1464 bytes
///I rounded it to 1500
#define PACKET_SIZE 1500


/* Record Flow Structure */
typedef struct record_flow
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

/// @brief Packet handler function for processing and exporting NetFlow records
/// 
/// This function processes captured packets and extracts NetFlow records for exporting.
/// It should be used in conjunction with pcap_loop for continuous packet processing.
///
/// @param user_data Additional arguments (unused in this context).
/// @param pkt_header PCAP packet header containing timestamp and packet information.
/// @param raw_packet Captured packet data containing the raw bytes of the packet.
/// 
/// @note This function should be used in conjunction with pcap_loop, as shown:
///       pcap_loop(handle, -1, packet_handler, NULL)
void handlePacket(u_char *user_data, const struct pcap_pkthdr *pkt_header, const u_char *raw_packet);

/// @brief Processes a packet to extract flow information and store it in a flow cache
///
/// This function takes a captured packet and extracts relevant flow information, 
/// storing it in the provided flow_cache vector.
///
/// @param raw_packet The captured packet data from which flow information is extracted.
/// @param uptime System uptime to correlate with the flow records.
/// @param flow_cache Pointer to a vector where the extracted flow records will be stored.
void processFlowCache(const u_char *raw_packet, time_t uptime, vector<record_flow> *flow_cache);

/// @brief Exports NetFlow packets based on the specified time and system uptime
///
/// This function handles the actual exporting of NetFlow packets using the provided
/// timestamp and system uptime.
///
/// @param export_time The time value structure representing the time of the export.
/// @param uptime System uptime to be included in the exported records.
/// @param flow_cache Pointer to a vector containing flow records to be exported.
void exportNetFlowPackets(const struct timeval export_time, time_t uptime, vector<record_flow> *flow_cache);

/// @brief Converts NetFlow records from network byte order to host byte order
///
/// This function modifies the provided NetFlow record to convert its fields from
/// network byte order (big-endian) to host byte order (the order used by the host machine).
///
/// @param flow_record Pointer to the NetFlow record to be converted.
void convertNetFlowToHostOrder(record_flow *flow_record);

/// @brief Populates a buffer with flow records for export
///
/// This function fills the provided buffer with flow records up to the specified number,
/// returning the total number of records written.
///
/// @param flow_cache Pointer to a vector of flow records to be exported.
/// @param max_records The number of records to populate in the buffer.
/// @param export_buffer Pointer to the buffer that will receive the flow records.
/// @return The number of records successfully written to the buffer.
int populateFlowBuffer(vector<record_flow> *flow_cache, int max_records, u_char *export_buffer);

/// @brief Populates a header buffer for NetFlow exports
///
/// This function fills the provided buffer with a header that includes the timestamp, 
/// system uptime, and count of flows, preparing it for export.
///
/// @param export_time The time value structure representing the time of the export.
/// @param uptime System uptime to include in the header.
/// @param flow_count The total number of flow records being exported.
/// @param header_buffer Pointer to the buffer where the header will be populated.
void populateHeaderBuffer(const struct timeval export_time, time_t uptime, int flow_count, u_char *header_buffer);
