// SnpNt32Io.c : Defines the entry point for the DLL application.
//
#include "SnpNt32Io.h"


static SNP_NIC_INFO mSnpNicInfo[MAX_NIC_NUMBER];
static UINT32       mNicCount;

static
INT32
SnpCheckLinkStatus (
  UINT8                   *Name
  )
{
  PPACKET_OID_DATA        OidData;
  LPADAPTER	              Adapter;
  INT32                   Success;
  INT32                   Ret;

  Adapter = PacketOpenAdapter(Name);

  if ((Adapter == NULL) || (Adapter->hFile == INVALID_HANDLE_VALUE)) {
    return -1;
  }

  //
  // Allocate a buffer then query the NIC driver to get the link state
  //
  OidData = malloc (sizeof(PACKET_OID_DATA) + sizeof(NDIS_LINK_STATE));

  if (OidData == NULL) {
    PacketCloseAdapter(Adapter);
    return -1;
  }

  OidData->Oid    = OID_GEN_LINK_STATE;
  OidData->Length = sizeof(NDIS_LINK_STATE);
  ZeroMemory (OidData->Data, sizeof(NDIS_LINK_STATE));

  Success = PacketRequest(Adapter, FALSE, OidData);
  PacketCloseAdapter(Adapter);

  if (Success) {
    Ret =  (((NDIS_LINK_STATE *)OidData->Data)->MediaConnectState == MediaConnectStateConnected) ? 0 : -1;
    free (OidData);
    return Ret;
  }

  free (OidData);
  return -1;
}

static
INT32
SnpGetMac (
  UINT8                   *Name,
  EFI_MAC_ADDRESS         *Mac
  )
{
  PPACKET_OID_DATA        OidData;
  LPADAPTER	              Adapter;
  INT32                   Success;
  INT32                   Index;

  Adapter = PacketOpenAdapter(Name);

  if ((Adapter == NULL) || (Adapter->hFile == INVALID_HANDLE_VALUE))	{
    return -1;
  }	

  // 
  // Allocate a buffer then query the NIC driver to get the MAC
  //

  OidData = malloc (sizeof(PACKET_OID_DATA) + NET_ETHER_ADDR_LEN);

  if (OidData == NULL) {
    PacketCloseAdapter(Adapter);
    return -1;
  }

  OidData->Oid    = OID_802_3_CURRENT_ADDRESS;
  OidData->Length = NET_ETHER_ADDR_LEN;
  ZeroMemory (OidData->Data, NET_ETHER_ADDR_LEN);

  Success = PacketRequest(Adapter, FALSE, OidData);
  for (Index = 0; Index < NET_ETHER_ADDR_LEN; Index++) {
    if ((OidData->Data)[Index] != 0) {
      break;
    }
  }
  if (Index == NET_ETHER_ADDR_LEN) {
    Success = 0;
  }

  if(Success)
  {
    printf("The MAC address of the adapter is %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
      (OidData->Data)[0],
      (OidData->Data)[1],
      (OidData->Data)[2],
      (OidData->Data)[3],
      (OidData->Data)[4],
      (OidData->Data)[5]);
  }

  PacketCloseAdapter(Adapter);

  if(Success) {
    CopyMemory (Mac, OidData->Data, NET_ETHER_ADDR_LEN);
    free (OidData);
    return 0;
  }

  free (OidData);
  return -1;
}

SNPNT32_IO_API 
INT32 
SnpFinalize (
  VOID
  )
{
  UINT32                  Index;

  for (Index = 0; Index < mNicCount; Index++) {
    pcap_close (mSnpNicInfo[Index].Pcap);
  }

  return 0;
}

SNPNT32_IO_API 
INT32 
SnpInitialize (
  UINT32                  *Num, 
  EFI_ADAPTER_INFO        *Adapters 
  )
{
  pcap_if_t               *AllDevs;
  pcap_if_t               *Dev;
  pcap_t                  *Pcap;
  EFI_MAC_ADDRESS         Mac;
  UINT32                  Count;
  UINT8                   ErrBuf [PCAP_ERRBUF_SIZE];


  Count = 0;

  //
  //Retrieve the device list 
  //
  if (pcap_findalldevs(&AllDevs, ErrBuf) == -1) {
    return -1;
  }


  for(Dev = AllDevs; Dev != NULL; Dev = Dev->next){
    Pcap = pcap_open_live (Dev->name, 65535, 1, 1, ErrBuf); 

    if (Pcap == NULL) {
      continue;
    }

    //
    // Only support the Ethernet
    //
    if (pcap_datalink (Pcap) != DLT_EN10MB) {
      pcap_close (Pcap);
      continue;
    }

    if (SnpGetMac (Dev->name, &Mac) != 0) {
      pcap_close (Pcap);
      continue;
    }

    if (SnpCheckLinkStatus(Dev->name) != 0) {
      pcap_close (Pcap);
      continue;
    }

    mSnpNicInfo[Count].Interface = Dev;
    mSnpNicInfo[Count].Pcap      = Pcap;
    mSnpNicInfo[Count].Mac       = Mac; 

    Adapters[Count].Index        = Count;
    Adapters[Count].Mac          = Mac;

    Count++;
  }

  pcap_freealldevs (AllDevs);

  printf("Number of NICs found: %d\n", Count);

  *Num = Count;
  return 1;
}

SNPNT32_IO_API
INT32 
SnpSetReceiveFilter (
  UINT32                  Index, 
  UINT32                  Enable, 
  UINT32                  MCastFilterCnt,
  EFI_MAC_ADDRESS         *MCastFilter
  )
{
  char *FilterString;
  char MCastString[SNP_MCAST_LEN];

  const char * pPromiscuousMulticast = "(multicast)";
  const char * pUnicast = "(not multicast and not broadcast)";
  const char * pBroadcast = "(broadcast)";

  struct bpf_program fcode;
  u_int NetMask = 0xffffffff;
  u_int i;

  pcap_t * handle = mSnpNicInfo[Index].Pcap;

  FilterString = malloc (SNP_FILTER_LEN + SNP_MCAST_LEN * MCastFilterCnt);
  if (FilterString == NULL) {
    return -1;
  }

  FilterString[0] = 0;

  if (EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS == (Enable & EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS)) {
    strcpy (FilterString,pUnicast);
    strcat (FilterString," or ");
    strcat (FilterString,pBroadcast);
    strcat (FilterString," or ");
    strcat (FilterString,pPromiscuousMulticast);
    goto SetFilter;  
  }

  if (EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS_MULTICAST == (Enable & EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS_MULTICAST)) {
    if (strlen (FilterString) != 0) {
      strcat (FilterString, " or ");
    }
    strcat (FilterString,pPromiscuousMulticast);
  }

  if (EFI_SIMPLE_NETWORK_RECEIVE_UNICAST == (Enable & EFI_SIMPLE_NETWORK_RECEIVE_UNICAST)) {
    if (strlen (FilterString) != 0) {
      strcat (FilterString, " or ");
    }
    strcat (FilterString,pUnicast);
  }

  if (EFI_SIMPLE_NETWORK_RECEIVE_BROADCAST == (Enable & EFI_SIMPLE_NETWORK_RECEIVE_BROADCAST)){
    if (strlen (FilterString) != 0) {
      strcat (FilterString, " or ");
    }
    strcat (FilterString,pBroadcast);
  }

  if (EFI_SIMPLE_NETWORK_RECEIVE_MULTICAST == (Enable & EFI_SIMPLE_NETWORK_RECEIVE_MULTICAST) && MCastFilterCnt > 0 && 0 == (Enable & EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS_MULTICAST)) {

    for (i=0; i < MCastFilterCnt;i++) {
      if (strlen (FilterString) != 0) {
        strcat (FilterString, " or ");
      }
      strcat (FilterString, "(ether dst ");
      sprintf (MCastString, "%02x:%02x:%02x:%02x:%02x:%02x)",
        MCastFilter[i].Addr[0],
        MCastFilter[i].Addr[1],
        MCastFilter[i].Addr[2],
        MCastFilter[i].Addr[3],
        MCastFilter[i].Addr[4],
        MCastFilter[i].Addr[5]);
      strcat (FilterString, MCastString);
    }

  }

SetFilter:
  printf ("The Fiter String used is %s\n",FilterString);

  //compile the filter
  if (pcap_compile(handle, &fcode,FilterString, 1, NetMask) < 0 ){
    printf ("\nUnable to compile the packet filter. Check the syntax.\n");
    free (FilterString);
    return -1;
  }

  //set the filter
  if (pcap_setfilter (handle, &fcode)<0) {
    printf("\nError setting the filter.\n");
    free (FilterString);
    return -1;
  }

  free (FilterString);
  return 1;
}

SNPNT32_IO_API 
INT32 
SnpReceive (
  UINT32                  Index,
  UINT32                  *BufferSize,
  UINT8                   *Buffer
  )
{
  INT32                   Result;
  struct pcap_pkthdr      *Head;
  UINT8                   *Data;
  pcap_t                  *Pcap;
  UINT32                  CopyLen;

  Pcap = mSnpNicInfo[Index].Pcap;

  Result = pcap_next_ex (Pcap, &Head, &Data);

  if (Result == 1) {
    CopyLen = (Head->len <= *BufferSize) ? Head->len : *BufferSize;
    *BufferSize = Head->len;
    CopyMemory (Buffer, Data, CopyLen);
  }

  return Result;
}

SNPNT32_IO_API 
INT32 
SnpTransmit (
  UINT32                  Index, 
  UINT32                  HeaderSize,
  UINT32                  BufferSize,
  UINT8                   *Buffer,
  EFI_MAC_ADDRESS         *SrcAddr,
  EFI_MAC_ADDRESS         *DestAddr,
  UINT16                  *Protocol
  )
{
  ETHERNET_HEADER         *Frame;
  UINT16                  ProtocolNet;
  pcap_t                  * Pcap;

  Pcap = mSnpNicInfo[Index].Pcap;

  //
  // Construct the frame header if no already presented
  //
  if (HeaderSize != 0) {
    Frame       = (ETHERNET_HEADER *)Buffer;
    ProtocolNet = NTOHS(*Protocol);

    CopyMemory (Frame->SrcMac,     SrcAddr,      NET_ETHER_ADDR_LEN);
    CopyMemory (Frame->DstMac,     DestAddr,     NET_ETHER_ADDR_LEN);
    CopyMemory (&Frame->Protocol, &ProtocolNet, sizeof(UINT16));  
  }

  if (pcap_sendpacket (Pcap, Buffer, (int)BufferSize) == -1) {
    return -1;
  }

  return 0;
}

BOOL APIENTRY 
DllMain ( 
  HANDLE                        hModule, 
  DWORD                         ul_reason_for_call, 
  LPVOID                        lpReserved
  )
{
  return TRUE;
}
