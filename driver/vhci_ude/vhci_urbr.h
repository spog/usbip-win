#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <usbdi.h>

#include "usb_cspkt.h"

#include "vhci_dev.h"

typedef enum {
	URBR_TYPE_URB,
	URBR_TYPE_UNLINK,
	URBR_TYPE_SELECT_CONF,
	URBR_TYPE_SELECT_INTF,
	URBR_TYPE_RESET_PIPE
} urbr_type_t;

typedef struct _urb_req {
	pctx_ep_t	ep;
	WDFREQUEST	req;
	urbr_type_t	type;
	unsigned long	seq_num;
	union {
		PURB	urb;
		unsigned long	seq_num_unlink;
		UCHAR	conf_value;
		struct {
			UCHAR	intf_num, alt_setting;
		} intf;
	} u;
	LIST_ENTRY	list_all;
	LIST_ENTRY	list_state;
	/* back reference to WDFMEMORY for deletion */
	WDFMEMORY	hmem;
} urb_req_t, *purb_req_t;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(urb_req_t, TO_URBR)

#define IS_TRANSFER_FLAGS_IN(flags)	((flags) & USBD_TRANSFER_DIRECTION_IN)

#define RemoveEntryListInit(le)	do { RemoveEntryList(le); InitializeListHead(le); } while (0)

extern struct usbip_header *get_hdr_from_req_read(WDFREQUEST req_read);
extern PVOID get_data_from_req_read(WDFREQUEST req_read, ULONG length);

extern ULONG get_read_payload_length(WDFREQUEST req_read);

extern PVOID get_buf(PVOID buf, PMDL bufMDL);

extern NTSTATUS
copy_to_transfer_buffer(PVOID buf_dst, PMDL bufMDL, int dst_len, PVOID src, int src_len);

extern void set_cmd_submit_usbip_header(struct usbip_header *hdr, unsigned long seqnum, unsigned int devid,
	unsigned int direct, pctx_ep_t ep, unsigned int flags, unsigned int len);
extern void set_cmd_unlink_usbip_header(struct usbip_header *h, unsigned long seqnum, unsigned int devid,
	unsigned long seqnum_unlink);

extern void
build_setup_packet(usb_cspkt_t *csp, unsigned char direct_in, unsigned char type, unsigned char recip, unsigned char request);

extern NTSTATUS
submit_req_urb(pctx_ep_t ep, WDFREQUEST req);
extern NTSTATUS
submit_req_select(pctx_ep_t ep, WDFREQUEST req, BOOLEAN is_select_conf, UCHAR conf_value, UCHAR intf_num, UCHAR alt_setting);
extern NTSTATUS
submit_req_reset_pipe(pctx_ep_t ep, WDFREQUEST req);
extern NTSTATUS
store_urbr(WDFREQUEST req_read, purb_req_t urbr);

extern void
complete_urbr(purb_req_t urbr, NTSTATUS status);

#if 1 /*spog - added*/
static const char* get_descriptor = "GET_DESCRIPTOR";
static const char* get_descriptor_request_device = "GET_DESCRIPTOR Request DEVICE";
static const char* get_descriptor_request_configuration = "GET_DESCRIPTOR Request CONFIGURATION";
static const char* get_descriptor_request_string = "GET_DESCRIPTOR Request STRING";
static const char* set_configuration = "SET_CONFIGURATION";
static const char* urb_control_in = "URB_CONTROL in";
static const char* urb_control_out = "URB_CONTROL out";
static const char* unknown_bRequest = "Unknown 'bRequest' - xxx";
static const char* unknown_bDescriptorType = "Unknown 'bDescriptorType' - xxx";
static const char* no_more_info = "-";

static inline const char* urbr_more_info_from_setup_packet(UCHAR* setup_packet)
{
	switch (setup_packet[0]) { /*bmRequestType*/
	case 0x80: /**/
		switch (setup_packet[1]) { /*bRequest*/
		case 0x06: /*GET DESCRIPTOR*/
			switch (setup_packet[3]) { /*bDescriptorType*/
			case 0x01: return get_descriptor_request_device;
			case 0x02: return get_descriptor_request_configuration;
			case 0x03: return get_descriptor_request_string;
			}
			return unknown_bDescriptorType;
		}
	case 0x00: /**/
		switch (setup_packet[1]) { /*bRequest*/
		case 0x09: /*SET CONFIGURATION*/
			return set_configuration;
		}
		return unknown_bRequest;
	case 0xa1: return urb_control_in;
	case 0x21: return urb_control_out;
	}
	return unknown_bRequest;
}

static inline const char* urbr_more_info(purb_req_t urbr)
{
	PURB urb = urbr->u.urb;
	USHORT urb_func = urb->UrbHeader.Function;

	switch (urb_func) {
	case URB_FUNCTION_GET_STATUS_FROM_DEVICE:
	case URB_FUNCTION_GET_STATUS_FROM_INTERFACE:
	case URB_FUNCTION_GET_STATUS_FROM_ENDPOINT:
	case URB_FUNCTION_GET_STATUS_FROM_OTHER:
		return no_more_info;
	case URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE:
		return no_more_info;
	case URB_FUNCTION_GET_DESCRIPTOR_FROM_INTERFACE:
		return no_more_info;
	case URB_FUNCTION_CONTROL_TRANSFER:
		return urbr_more_info_from_setup_packet(((struct _URB_CONTROL_TRANSFER*)urb)->SetupPacket);
	case URB_FUNCTION_CONTROL_TRANSFER_EX:
		return urbr_more_info_from_setup_packet(((struct _URB_CONTROL_TRANSFER_EX*)urb)->SetupPacket);
	case URB_FUNCTION_CLASS_DEVICE:
	case URB_FUNCTION_CLASS_INTERFACE:
	case URB_FUNCTION_CLASS_ENDPOINT:
	case URB_FUNCTION_CLASS_OTHER:
	case URB_FUNCTION_VENDOR_DEVICE:
	case URB_FUNCTION_VENDOR_INTERFACE:
	case URB_FUNCTION_VENDOR_ENDPOINT:
		return no_more_info;
	case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER:
		return no_more_info;
	case URB_FUNCTION_ISOCH_TRANSFER:
		return no_more_info;
#if 0
	case URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL:
		return no_more_info;
#endif
	}
	return no_more_info;

}
#endif
