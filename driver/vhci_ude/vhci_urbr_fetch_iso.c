#include "vhci_driver.h"
#include "vhci_urbr_fetch_iso.tmh"

#include "usbip_proto.h"
#include "vhci_urbr.h"
#include "usbd_helper.h"

static BOOLEAN
save_iso_desc(struct _URB_ISOCH_TRANSFER *urb, struct usbip_iso_packet_descriptor *iso_desc)
{
	ULONG	i;

	TRD(WRITE, "urb->NumberOfPackets=%d", urb->NumberOfPackets);
	for (i = 0; i < urb->NumberOfPackets; i++) {
		TRD(WRITE, "urb->IsoPacket[%d].Offset=%u, iso_desc: offset=0x%x, length=%u, actual_length=%u", i, urb->IsoPacket[i].Offset, iso_desc->offset, iso_desc->length, iso_desc->actual_length);
		if (iso_desc->offset > urb->IsoPacket[i].Offset) {
			TRW(WRITE, "why offset changed?%d 0x%x %u %u %u", i, iso_desc->offset, iso_desc->length, iso_desc->actual_length, urb->IsoPacket[i].Offset);
			iso_desc++;
			TRW(WRITE, "why offset changed?%d 0x%x %u %u %u", i, iso_desc->offset, iso_desc->length, iso_desc->actual_length, urb->IsoPacket[i].Offset);
			return FALSE;
		}
		urb->IsoPacket[i].Length = iso_desc->actual_length;
		urb->IsoPacket[i].Status = to_usbd_status(iso_desc->status);
		iso_desc++;
	}
	return TRUE;
}

static void
fetch_iso_data(char *dest, ULONG dest_len, char *src, ULONG src_len, struct _URB_ISOCH_TRANSFER *urb)
{
	ULONG	i;
	ULONG	offset = 0;

	for (i = 0; i < urb->NumberOfPackets; i++) {
		if (urb->IsoPacket[i].Length == 0)
			continue;

		if (urb->IsoPacket[i].Offset + urb->IsoPacket[i].Length > dest_len) {
			TRW(WRITE, "Warning, why this?");
			break;
		}
		if (offset + urb->IsoPacket[i].Length > src_len) {
			TRE(WRITE, "Warning, why that?");
			break;
		}
		RtlCopyMemory(dest + urb->IsoPacket[i].Offset, src + offset, urb->IsoPacket[i].Length);
		offset += urb->IsoPacket[i].Length;
	}
	if (offset != src_len) {
		TRW(WRITE, "why not equal offset:%d src_len:%d", offset, src_len);
	}
}

NTSTATUS
fetch_urbr_iso(PURB urb, struct usbip_header *hdr)
{
	struct _URB_ISOCH_TRANSFER *urb_iso = &urb->UrbIsochronousTransfer;
	struct usbip_iso_packet_descriptor *iso_desc;
	PVOID	buf;
	int	in_len = 0;

	TRD(WRITE, "sizeof: usbip_header=%d, usbip_is_packet_descriptor=%d", sizeof(struct usbip_header), sizeof(struct usbip_iso_packet_descriptor));
	TRD(WRITE, "ret_submit: status=%d, actual_length=%d, start_frame=%d", hdr->u.ret_submit.status, hdr->u.ret_submit.actual_length, hdr->u.ret_submit.start_frame);
	TRD(WRITE, "ret_submit: number_of_packets=%d, error_count=%d", hdr->u.ret_submit.number_of_packets, hdr->u.ret_submit.error_count);
	if (IS_TRANSFER_FLAGS_IN(urb_iso->TransferFlags))
		in_len = hdr->u.ret_submit.actual_length;
	TRD(WRITE, "urb_iso->TransferFlags = 0x%x, urb_iso->TransferBufferLength = %d, in_len = %d", urb_iso->TransferFlags, urb_iso->TransferBufferLength, in_len);
	iso_desc = (struct usbip_iso_packet_descriptor*)((char*)(hdr + 1) + in_len);
	if (!save_iso_desc(urb_iso, iso_desc))
		return STATUS_INVALID_PARAMETER;

	urb_iso->ErrorCount = hdr->u.ret_submit.error_count;
#if 1 /*spog - added*/
	if (!IS_TRANSFER_FLAGS_IN(urb_iso->TransferFlags))
		return STATUS_SUCCESS;
#endif
	buf = get_buf(urb_iso->TransferBuffer, urb_iso->TransferBufferMDL);
	if (buf == NULL)
		return STATUS_INVALID_PARAMETER;
	fetch_iso_data(buf, urb_iso->TransferBufferLength, (char *)(hdr + 1), hdr->u.ret_submit.actual_length, urb_iso);
	urb_iso->TransferBufferLength = hdr->u.ret_submit.actual_length;
	return STATUS_SUCCESS;
}
