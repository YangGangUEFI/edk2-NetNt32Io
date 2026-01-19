#ifndef __EFI_SNPNT32_IO_H__
#define __EFI_SNPNT32_IO_H__

#include "pcap.h"
#include "packet32.h"
#include "ntddndis.h"

#ifdef SNPNT32IO_EXPORTS
#define SNPNT32_IO_API __declspec(dllexport)
#else
#define SNPNT32_IO_API __declspec(dllimport)
#endif

#define NTOHS(x)           \
  (UINT16) ((((UINT16)(x) & 0xff) << 8) | (((UINT16)(x) & 0xff00) >> 8))

enum {
  EFI_SIMPLE_NETWORK_RECEIVE_UNICAST     = 0x01,
  EFI_SIMPLE_NETWORK_RECEIVE_MULTICAST   = 0x02,
  EFI_SIMPLE_NETWORK_RECEIVE_BROADCAST   = 0x04,
  EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS = 0x08,
  EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS_MULTICAST = 0x10,

  SNP_FILTER_LEN     = 200,
  SNP_MCAST_LEN      = 25,
  NET_ETHER_ADDR_LEN = 6,
  MAX_NIC_NUMBER        = 16,
};

typedef struct {
  UINT8                   Addr[32];
} EFI_MAC_ADDRESS;


typedef struct {
  pcap_if_t               *Interface;
  pcap_t                  *Pcap;
  EFI_MAC_ADDRESS         Mac;
} SNP_NIC_INFO;

#pragma pack(1)
typedef struct {
  UINT8                   DstMac [NET_ETHER_ADDR_LEN];
  UINT8                   SrcMac [NET_ETHER_ADDR_LEN];
  UINT16                  Protocol;
} ETHERNET_HEADER;
#pragma pack()

//
// The interface between the EFI SnpNt32 driver and this DLL,
// keep these two parts in sync.
//
#pragma pack(1)
typedef struct {
  UINT32                  Index;
  EFI_MAC_ADDRESS         Mac;
} EFI_ADAPTER_INFO;
#pragma pack()

SNPNT32_IO_API
INT32
SnpInitialize (
               UINT32                  *AdapterCnt,
               EFI_ADAPTER_INFO        *AdapterInfo
               );

SNPNT32_IO_API
INT32
SnpFinalize (
             VOID
             );

SNPNT32_IO_API
INT32
SnpSetReceiveFilter (
                     UINT32                  Index,
                     UINT32                  Enable,
                     UINT32                  MCastFilterCnt,
                     EFI_MAC_ADDRESS         *MCastFilter
                     );

SNPNT32_IO_API
INT32
SnpReceive (
            UINT32                  Index,
            UINT32                  *BufferSize,
            UINT8                   *Buffer
            );

SNPNT32_IO_API
INT32
SnpTransmit (
             UINT32                  Index,
             UINT32                  HeaderSize,
             UINT32                  BufferSize,
             VOID                    *Buffer,
             EFI_MAC_ADDRESS         *SrcAddr,
             EFI_MAC_ADDRESS         *DestAddr,
             UINT16                  *Protocol
             );
#endif
