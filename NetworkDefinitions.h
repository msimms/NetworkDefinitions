//	MIT License
//
//  Copyright © 2017 Michael J Simms. All rights reserved.
//
//	Permission is hereby granted, free of charge, to any person obtaining a copy
//	of this software and associated documentation files (the "Software"), to deal
//	in the Software without restriction, including without limitation the rights
//	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//	copies of the Software, and to permit persons to whom the Software is
//	furnished to do so, subject to the following conditions:
//
//	The above copyright notice and this permission notice shall be included in all
//	copies or substantial portions of the Software.
//
//	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//	SOFTWARE.

#pragma once

#include <stdint.h>

#define MAC_ADDR_SIZE 6

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1
#endif

typedef enum EtherType
{
	ETHER_UNKNOWN                      = 0x0000,
	ETHER_TYPE_OLD                     = 0x05DC,
	ETHER_TYPE_IDP                     = 0x0600,
	ETHER_TYPE_IP4                     = 0x0800,
	ETHER_TYPE_ARP                     = 0x0806,
	ETHER_TYPE_RARP                    = 0x8035,
	ETHER_TYPE_APPLETALK               = 0x809b,
	ETHER_TYPE_AARP                    = 0x80f3,
	ETHER_TYPE_IEEE_802_1_TAGGED_FRAME = 0x8100,
	ETHER_TYPE_NOVELL_IPX              = 0x8137,
	ETHER_TYPE_NOVELL                  = 0x8138,
	ETHER_TYPE_IP6                     = 0x86DD,
	ETHER_TYPE_MPLS_UNICAST            = 0x8847,
	ETHER_TYPE_MPLS_MULTICAST          = 0x8848,
	ETHER_TYPE_PPOE_DISCOVERY          = 0x8863,
	ETHER_TYPE_PPOE_SESSION            = 0x8864
} EtherType;

typedef enum IpType
{
	IP_UNKNOWN           = 0x00,
	IP_ICMP              = 0x01,
	IP_IGMP              = 0x02,
	IP_GGP               = 0x03,
	IP_IP4_ENCAPSULATION = 0x04,
	IP_ST                = 0x05,
	IP_TCP               = 0x06,
	IP_CBT               = 0x07,
	IP_EGP               = 0x08,
	IP_IGP               = 0x09,
	IP_BBN_RCC_MON       = 0x0A,
	IP_NVP_II            = 0x0B,
	IP_PUP               = 0x0C,
	IP_ARGUS             = 0x0D,
	IP_EMCON             = 0x0E,
	IP_XNET              = 0x0F,
	IP_CHAOS             = 0x10,
	IP_UDP               = 0x11,
	IP_MUX               = 0x12,
	IP_DCN_MEAS          = 0x13,
	IP_HMP               = 0x14,
	IP_PRM               = 0x15,
	IP_XNS_IDP           = 0x16,
	IP_TRUNK_1           = 0x17,
	IP_TRUNK_2           = 0x18,
	IP_LEAF_1            = 0x19,
	IP_LEAF_2            = 0x1A,
	IP_RDP               = 0x1B,
	IP_IRTP              = 0x1C,
	IP_ISO_TP4           = 0x1D,
	IP_NETBLT            = 0x1E,
	IP_MFE_NSP           = 0x1F,
	IP_MERIT_INP         = 0x20,
	IP_DCCP              = 0x21,
	IP_3PC               = 0x22,
	IP_IDPR              = 0x23,
	IP_XTP               = 0x24,
	IP_DDP               = 0x25,
	IP_IDPR_CMTP         = 0x26,
	IP_TPpp              = 0x27,
	IP_IL                = 0x28,
	IP_IPV6              = 0x29,
	IP_SDRP              = 0x2A,
	IP_IPV6_Route        = 0x2B,
	IP_IPV6_Frag         = 0x2C,
	IP_IDRP              = 0x2D,
	IP_RSVP              = 0x2E,
	IP_GRE               = 0x2F,
	IP_MHRP              = 0x30,
	IP_BNA               = 0x31,
	IP_ESP               = 0x32,
	IP_AH                = 0x33,
	IP_I_NLSP            = 0x34,
	IP_SWIPE             = 0x35,
	IP_NARP              = 0x36,
	IP_MOBILE            = 0x37,
	IP_TLSP              = 0x38,
	IP_SKIP              = 0x39,
	IP_IPV6_ICMP         = 0x3A,
	IP_IPV6_NoNxt        = 0x3B,
	IP_IPV6_Opts         = 0x3C
} IpType;

typedef enum IpFlagsType
{
	IP_OPTION_NONE           = 0x00,
	IP_OPTION_RESERVED       = 0x00,
	IP_OPTION_DONT_FRAGMENT  = 0x40,
	IP_OPTION_MORE_FRAGMENTS = 0x20
} IpFlagsType;

typedef enum IcmpV4Type
{
	ICMPV4_ECHO_REPLY = 0,
	ICMPV4_RESERVED1,
	ICMPV4_RESERVED2,
	ICMPV4_DESTINATION_UNREACHABLE,
	ICMPV4_SOURCE_QUENCH,
	ICMPV4_REDIRECT_MESSAGE,
	ICMPV4_RESERVED_ALTERNATE_HOST_ADDR,
	ICMPV4_RESERVED7,
	ICMPV4_ECHO_REQUEST,
	ICMPV4_ROUTER_ADVERTISEMENT,
	ICMPV4_ROUTER_SOLICITATION,
	ICMPV4_TIME_EXCEEDED,
	ICMPV4_PARAMETER_PROBLEM,
	ICMPV4_TIMESTAMP,
	ICMPV4_TIMESTAMP_REPLY,
	ICMPV4_INFORMATION_REQUEST,
	ICMPV4_INFORMATION_REPLY,
	ICMPV4_ADDRESS_MASK_REQUEST,
	ICMPV4_ADDRESS_MASK_REPLY,
	ICMPV4_RESERVED19,
	ICMPV4_RESERVED20,
	ICMPV4_RESERVED21,
	ICMPV4_RESERVED22,
	ICMPV4_RESERVED23,
	ICMPV4_RESERVED24,
	ICMPV4_RESERVED25,
	ICMPV4_RESERVED26,
	ICMPV4_RESERVED27,
	ICMPV4_RESERVED28,
	ICMPV4_RESERVED29,
	ICMPV4_TRACEROUTE,
	ICMPV4_DATAGRAM_CONVERSION_ERROR,
	ICMPV4_MOBILE_HOST_REDIRECT,
	ICMPV4_WHERE_ARE_YOU,
	ICMPV4_HERE_I_AM,
	ICMPV4_MOBILE_REGISTRATION_REQUEST,
	ICMPV4_MOBILE_REGISTRATION_REPLY,
	ICMPV4_DOMAIN_NAME_REQUEST,
	ICMPV4_DOMAIN_NAME_REPLY,
	ICMPV4_SKIP_ALGORITHM_DISCOVERY_PROTOCOL,
	ICMPV4_PHOTURIS
} IcmpV4Type;

typedef enum IcmpV6Type
{
	ICMPV6_DESTINATION_UNREACHABLE = 0,
	ICMPV6_PACKET_TOO_BIG,
	ICMPV6_TIME_EXCEEDED,
	ICMPV6_PARAMETER_PROBLEM,
	ICMPV6_ECHO_REQUEST = 128,
	ICMPV6_ECHO_REPLY,
	ICMPV6_MULTICAST_LISTENER_QUERY,
	ICMPV6_MULTICAST_LISTENER_REPORT,
	ICMPV6_MULTICAST_LISTENER_DONE,
	ICMPV6_MULTICAST_ROUTER_SOLICITATION,
	ICMPV6_MULTICAST_ROUTER_ADVERTISEMENT,
	ICMPV6_MULTICAST_NEIGHBOR_SOLICITATION,
	ICMPV6_MULTICAST_NEIGHBOR_ADVERTISEMENT,
	ICMPV6_MULTICAST_REDIRECT_MESSAGE,
	ICMPV6_MULTICAST_ROUTER_RENUMBERING,
	ICMPV6_MULTICAST_ICMP_NODE_INFORMATION_QUERY,
	ICMPV6_MULTICAST_ICMP_NODE_INFORMATION_RESPONSE
} IcmpV6Type;

typedef enum ArpType
{
	ARP_REQUEST = 1,
	ARP_REPLY   = 2
} ArpType;

typedef enum DhcpOpCode
{
	DHCP_OPCODE_REQUEST = 1,
	DHCP_OPCODE_REPLY
} DhcpOpCode;

typedef enum DhcpHardwareType
{
	DHCP_HARDWARE_ETHERNET = 1,
	DHCP_HARDWARE_EXPERIMENTAL_ETHERNET,
	DHCP_HARDWARE_AMATEUR_RADIO_AX_25,
	DHCP_HARDWARE_PROTEON_PRONET,
	DHCP_HARDWARE_CHAOS,
	DHCP_HARDWARE_IEEE_802,
	DHCP_HARDWARE_ARCNET,
	DHCP_HARDWARE_HYPERCHANNEL,
	DHCP_HARDWARE_LANSTAR,
	DHCP_HARDWARE_AUTONET_SHORT_ADDRESS,
	DHCP_HARDWARE_LOCALTALK,
	DHCP_HARDWARE_LOCALNET,
	DHCP_HARDWARE_ULTRA_LINK,
	DHCP_HARDWARE_SMDS,
	DHCP_HARDWARE_FRAME_RELAY,
	DHCP_HARDWARE_ATM_1,
	DHCP_HARDWARE_HDLC,
	DHCP_HARDWARE_FIBRE_CHANNEL,
	DHCP_HARDWARE_ATM_2,
	DHCP_HARDWARE_SERIAL_LINE,
	DHCP_HARDWARE_ATM_3,
	DHCP_HARDWARE_MIL_STD_1394_1995,
	DHCP_HARDWARE_MAPOS,
	DHCP_HARDWARE_TWINAXIAL,
	DHCP_HARDWARE_EUI_64,
	DHCP_HARDWARE_HIPARP,
	DHCP_HARDWARE_IP_ARP_OVER_ISO_7816_3,
	DHCP_HARDWARE_ARPSEC,
	DHCP_HARDWARE_IPSEC_TUNNEL,
	DHCP_HARDWARE_INFINIBAND,
	DHCP_HARDWARE_CAI_TIA_102,
	DHCP_HARDWARE_WIEGAND_INTERFACE,
	DHCP_HARDWARE_PURE_IP
} DhcpHardwareType;

typedef enum DhcpV4MessageType
{
	DHCP4_MSG_UNKNOWN = 0,
	DHCP4_MSG_DISCOVER,
	DHCP4_MSG_OFFER,
	DHCP4_MSG_REQUEST,
	DHCP4_MSG_DECLINE,
	DHCP4_MSG_ACK,
	DHCP4_MSG_NACK,
	DHCP4_MSG_RELEASE,
	DHCP4_MSG_INFORM,
	DHCP4_MSG_DHCP_FORCE_RENEW,
	DHCP4_MSG_LEASE_QUERY,
	DHCP4_MSG_LEASE_UNASSIGNED,
	DHCP4_MSG_LEASE_UNKNOWN,
	DHCP4_MSG_LEASE_ACTIVE,
	DHCP4_MSG_BULK_LEASE_QUERY,
	DHCP4_MSG_LEASE_QUERY_DONE,
	DHCP4_MSG_ACTIVE_LEASE_QUERY,
	DHCP4_MSG_LEASE_QUERY_STATUS,
	DHCP4_MSG_TLS
} DhcpV4MessageType;

#pragma pack(push, 1)

typedef struct EthernetHeader
{
	uint8_t  destinationMac[MAC_ADDR_SIZE];
	uint8_t  sourceMac[MAC_ADDR_SIZE];
	uint16_t etherType;
} EthernetHeader;

typedef struct EthernetArpPacket
{
	uint16_t hardwareType;
	uint16_t protocolType;
	uint8_t  hardwareTypeLen;
	uint8_t  protocolTypeLen;
	uint16_t operation;
	uint8_t  senderHardwareAddr[MAC_ADDR_SIZE];
	uint32_t senderProtocolAddr;
	uint8_t  targetHardwareAddr[MAC_ADDR_SIZE];
	uint32_t targetProtocolAddr;
} EthernetArpPacket;

typedef uint32_t IpV4Addr;

typedef struct IpV6Addr
{
	uint8_t bytes[16];
} IpV6Addr;

typedef struct IpAddr
{
	union
	{
		IpV4Addr v4Addr;
		IpV6Addr v6Addr;
	} ip;
	EtherType type;
} IpAddr;

typedef struct IpHeaderV4
{
#if LITTLE_ENDIAN
	uint8_t  version;
	uint8_t  headerLen;
#else
	uint8_t  headerLen;
	uint8_t  version;
#endif
	uint8_t  dscpAndEcn;
	uint16_t totalLength;
	uint16_t identification;
	uint16_t flagsAndFragOffset;
	uint8_t  ttl;
	uint8_t  protocol;
	uint16_t checksum;
	uint32_t sourceIp;
	uint32_t destIp;
} IpHeaderV4;

typedef struct IpHeaderV6
{
	uint32_t  versClassFlow;
	uint16_t  payloadLen;
	uint8_t   nextHeader;
	uint8_t   hopLimit;
	IpV6Addr  sourceAddr;
	IpV6Addr  destAddr;
} IpHeaderV6;

typedef struct IcmpV4Header
{
	uint8_t   type;
	uint8_t   code;
	uint16_t  checksum;
	uint32_t  rest;
} IcmpV4Header;

typedef struct IcmpV6Header
{
	uint8_t   type;
	uint8_t   code;
	uint16_t  checksum;
	uint32_t  reserved;
} IcmpV6Header;

typedef struct IgmpHeader
{
	uint8_t   type;
	uint8_t   maxRespTime;
	uint16_t  checksum;
	uint32_t  groupAddress;
} IgmpHeader;

typedef struct TcpHeader
{
	uint16_t sourcePort;
	uint16_t destPort;
	uint32_t sequenceNum;
	uint32_t ackNum;
	uint8_t  offset;
	uint8_t  flags;
	uint16_t windowSize;
	uint16_t checksum;
	uint16_t urgent;
} TcpHeader;

typedef struct UdpHeader
{
	uint16_t sourcePort;
	uint16_t destPort;
	uint16_t length;
	uint16_t checksum;
} UdpHeader;

typedef struct NtpTimestamp
{
	uint32_t seconds;
	uint32_t fraction;
} NtpTimestamp;

typedef struct NtpPacket
{
	uint8_t      flags;
	uint8_t      peerClockStratum;
	uint8_t      peerPollingInterval;
	uint8_t      peerClockPrecision;
	uint32_t     rootDelay;
	uint32_t     rootDispersion;
	uint32_t     referenceId;
	NtpTimestamp referenceTimestamp;
	NtpTimestamp originTimestamp;
	NtpTimestamp receiveTimestamp;
	NtpTimestamp transmitTimestamp;
} NtpPacket;

typedef struct DhcpHeaderV4
{
	uint8_t  opcode;
	uint8_t  hardwareType;
	uint8_t  hardwareAddrLen;
	uint8_t  hopCount;
	uint32_t transactionId;
	uint16_t secondsElapsed;
	uint16_t flags;
	uint32_t clientIp;
	uint32_t yourIp;
	uint32_t nextServerIp;
	uint32_t relayAgentIp;
	uint8_t  clientMac[MAC_ADDR_SIZE];
	uint8_t  padding[10];
	uint8_t  serverHostName[64];
	uint8_t  bootFileName[128];
	uint32_t magicCookie;
} DhcpHeaderV4;

typedef struct DhcpHeaderV6
{
	uint8_t msgType;
	uint8_t transactionId[3];
} DhcpHeaderV6;

typedef struct DhcpOptionV6
{
	uint16_t code;
	uint16_t len;
} DhcpOptionV6;

typedef struct MdnsHeader
{
	uint16_t ident;
	uint16_t flags;
	uint16_t questions;
	uint16_t answerRRs;
	uint16_t authorityRRs;
	uint16_t additionalRRs;
} MdnsHeader;

typedef struct MdnsQueryInfo
{
	uint16_t type;
	uint16_t theClass;
} MdnsQueryInfo;

typedef struct MdnsAnswerInfo
{
	uint16_t type;
	uint16_t theClass;
	uint32_t ttl;
	uint16_t length;
} MdnsAnswerInfo;

#pragma pack(pop)
