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

#define PORT_TCPMUX 1
#define PORT_REMOTE_JOB_ENTRY 5
#define PORT_ECHO_PROTOCOL 7
#define PORT_DISCARD_PROTOCOL 9
#define PORT_WAKE_ON_LAN 9
#define PORT_SYSTAT 11
#define PORT_DAYTIME_PROTOCOL 13
#define PORT_NETSTAT 15
#define PORT_QOTD 17
#define PORT_MESSAGE_SEND_PROTOCOL 18
#define PORT_CHARGEN 19
#define PORT_FTP_DATA_TRANSFER 20
#define PORT_FTP_CONTROL 21
#define PORT_SSH 22
#define PORT_TELNET 23
#define PORT_SMTP 25
#define PORT_TIME_PROTOCOL 37
#define PORT_RAP 38
#define PORT_RLP 39
#define PORT_HOST_NAME_SERVER_PROTOCOL 42
#define PORT_WHOIS 43
#define PORT_TACACS_PLUS 49
#define PORT_RMCP 50
#define PORT_XNS_TIME_PROTOCOL 52
#define PORT_DNS 53
#define PORT_XNS_CLEARINGHOUSE 54
#define PORT_XNS_AUTH 56
#define PORT_XNS_MAIL 58
#define PORT_BOOTP_SERVER 67
#define PORT_BOOTP_CLIENT 68
#define PORT_TFTP 69
#define PORT_GOPHER 70
#define PORT_FINGER 79
#define PORT_HTTP 80
#define PORT_TORPARK_ROUTING 81
#define PORT_TORPARK_CONTROL 82
#define PORT_KERBEROS 88
#define PORT_NIC_HOST_NAME 101
#define PORT_ISO_TSAP 102
#define PORT_DICOM 104
#define PORT_CCSO_NAMESERVER 105
#define PORT_RTELNET 107
#define PORT_SNA 108
#define PORT_POP2 109
#define PORT_POP3 110
#define PORT_ONC_RPC 111
#define PORT_IDENT 113
#define PORT_SFTP 115
#define PORT_UUCP_MAPPING 117
#define PORT_SQL_SERVICES 118
#define PORT_NNTP 119
#define PORT_NTP 123
#define PORT_NXEDIT 126
#define PORT_DCE_ENDPOINT 135
#define PORT_MS_EPMAP 135
#define PORT_NETBIOS_NAME_SERVICE 137
#define PORT_NETBIOS_DGRAM_SERVICE 138
#define PORT_NETBIOS_SESSION_SERVICE 139
#define PORT_IMAP 143
#define PORT_BFTP 152
#define PORT_SGMP 153
#define PORT_DMSP 158
#define PORT_SNMP 161
#define PORT_SNMPTRAP 162
#define PORT_PRINT 170
#define PORT_XDMCP 177
#define PORT_BGP 179
#define PORT_IRC 194
#define PORT_SMUX 199
#define PORT_APPLETALK_ROUTING 201
#define PORT_QMTP 209
#define PORT_ANSI_Z39_50 210
#define PORT_IPX 213
#define PORT_MPP 218
#define PORT_IMAP_V3 220
#define PORT_ESRO 259
#define PORT_ARCISDMS 262
#define PORT_BGMP 264
#define PORT_HTTP_MGMT 280
#define PORT_NOVASTOR 308
#define PORT_APPLESHARE_ADMIN 311
#define PORT_TSP 318
#define PORT_PTP_EVENT 319
#define PORT_PTP_GENERAL 320
#define PORT_MATIP_TYPE_A 350
#define PORT_MATIP_TYPE_B 351
#define PORT_CLOANTO 356
#define PORT_RPC2PORTMAP 369
#define PORT_CODAAUTH2 370
#define PORT_CLEARCASE_ALDB
#define PORT_HP_DATA_ALARM 383
#define PORT_AURP 387
#define PORT_LDAP 389
#define PORT_DECNET_OVER_TCPIP 399
#define PORT_UPS 401
#define PORT_SLP 427
#define PORT_NNSP 433
#define PORT_MOBILE_IP_AGENT 434
#define PORT_HTTPS 443
#define PORT_SNPP 444
#define PORT_MS_ACTIVE_DIRECTORY 445
#define PORT_KERBEROS_SET_PWORD 464
#define PORT_SMTPS 465
#define PORT_TCPNETHSPSRV 475
#define PORT_RETROSPECT 497
#define PORT_ISAKMP_IKE 500
#define PORT_MODBUS 502
#define PORT_CITADEL 504
#define PORT_FCP 510
#define PORT_REXEC 512
#define PORT_COMSAT 512
#define PORT_RLOGIN 513
#define PORT_WHO 513
#define PORT_REMOTE_SHELL 514
#define PORT_SYSLOG 514
#define PORT_LINE_PRINTER_DAEMON 515
#define PORT_TALK 517
#define PORT_NTALK 518
#define PORT_EFS 520
#define PORT_RIP 520
#define PORT_RIPNG 521
#define PORT_NCP 524
#define PORT_TIMED 525
#define PORT_RPC 530
#define PORT_NETNEWS 532
#define PORT_NETWALL 533
#define PORT_UUCP 540
#define PORT_COMMERCE 542
#define PORT_KLOGIN 543
#define PORT_KSHELL 544
#define PORT_DHCPV6_CLIENT 546
#define PORT_DHCPV6_SERVER
#define PORT_AFP 548
#define PORT_NEW_WHO 550
#define PORT_RTSP 554
#define PORT_RFS_SERVER 556
#define PORT_RMONITOR 560
#define PORT_MONITOR 561
#define PORT_NNTPS 563
#define PORT_SMTP_SUBMISSION 587
#define PORT_FILEMAKER_WEB_SHARING 591
#define PORT_HTTP_RPC_EP_MAP 593
#define PORT_RELIABLE_SYSLOG 601
#define PORT_TUNNEL_PROFILE 604
#define PORT_ASF_RMCP_IPMI 623
#define PORT_IPP 631
#define PORT_RLZ_DBASE 635
#define PORT_LDAPS 636
#define PORT_MSDP 639
#define PORT_SUPPORTSOFT_NEXUS_REMOTE_CMD 641
#define PORT_SANITY 643
#define PORT_LABEL_DISTRIBUTION_PROTOCOL 646
#define PORT_DHCP_FAILOVER_1 647
#define PORT_RRP 648
#define PORT_IEE_MMS 651
#define PORT_SUPPORTSOFT_NEXUS_REMOTE_DATA 653
#define PORT_MMS_MMP 654
#define PORT_TINC_VPN 655
#define PORT_IBM_RMC 657
#define PORT_MAC_OS_SERVER_ADMIN 660
#define PORT_DOOM 666
#define PORT_ACAP 674
#define PORT_REALM_RUSD 688
#define PORT_VATP 690
#define PORT_MS_EXCHANGE_ROUTING 691
#define PORT_LINUX_HA_HEARTBEAT 694
#define PORT_IEEE_MMS_SSL 695
#define PORT_OLSR 698
#define PORT_EPP 700
#define PORT_LMP 701
#define PORT_IRIS_OVER_BEEP 702
#define PORT_SILC 706
#define PORT_MPLS 711
#define PORT_TBRPF 712
#define PORT_KERBEROS_ADMIN 749
#define PORT_KERBEROS_IV 750
#define PORT_KERBEROS_MASTER 751
#define PORT_KERBEROS_PASSWD 752
#define PORT_RRH 753
#define PORT_TELL_SEND 754
#define PORT_KRBUPDATE 760
#define PORT_CONSERVER 782
#define PORT_SPAM_ASSASSIN 783
#define PORT_MDBS_DAEMON 800
#define PORT_CERT_MGMT_PROTOCOL 829
#define PORT_NETCONF_OVER_SSH 830
#define PORT_NETCONF_OVER_BEEP 831
#define PORT_NETCONF_FOR_SOAP_OVER_HTTPS 832
#define PORT_NETCONF_FOR_SOAP_OVE_BEEP 833
#define PORT_ADOBE_FLASH 843
#define PORT_DHCP_FAILOVER_2 847
#define PORT_GDOI 848
#define PORT_DNS_OVER_TLS 853
#define PORT_ISCSI 860
#define PORT_OWAMP 861
#define PORT_TWAMP 862
#define PORT_RSYNC 873
#define PORT_BIND 953
#define PORT_FTPS_DATA 989
#define PORT_FTPS_CONTROL 990
#define PORT_NETNEWS_ADMIN 991
#define PORT_TELNET_OVER_TLS 992
#define PORT_IMAPS 993
#define PORT_IRCS 994
#define PORT_POP3S 995
#define PORT_MDNS 5353
#define PORT_HTTP_ALT 8080

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
	uint8_t  versionAndHdrLen;
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

#ifdef LITTLE_ENDIAN
#define IPV4_VERSION(hdr) ((hdr->versionAndHdrLen & 0xF0) >> 4)
#define IPV4_HDR_LEN(hdr) ((hdr->versionAndHdrLen & 0x0F) * 4)
#else
#define IPV4_VERSION(hdr) ((hdr->versionAndHdrLen & 0x0F) * 4)
#define IPV4_HDR_LEN(hdr) ((hdr->versionAndHdrLen & 0xF0) >> 4)
#endif

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

typedef struct DnsHeader
{
	uint16_t ident;
	uint16_t flags;
	uint16_t questions;
	uint16_t answerRRs;
	uint16_t authorityRRs;
	uint16_t additionalRRs;
} DnsHeader;

typedef struct DnsQueryInfo
{
	uint16_t type;
	uint16_t theClass;
} DnsQueryInfo;

typedef struct DnsAnswerInfo
{
	uint16_t type;
	uint16_t theClass;
	uint32_t ttl;
	uint16_t length;
} DnsAnswerInfo;

typedef DnsHeader MdnsHeader;
typedef DnsQueryInfo MdnsQueryInfo;
typedef DnsAnswerInfo MdnsAnswerInfo;

#pragma pack(pop)
