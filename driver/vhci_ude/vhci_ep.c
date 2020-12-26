#include "vhci_driver.h"
#include "vhci_ep.tmh"

extern WDFQUEUE
create_queue_ep(pctx_ep_t ep);

static VOID
ep_start(_In_ UDECXUSBENDPOINT ude_ep)
{
	pctx_ep_t	ep = TO_EP(ude_ep);

	TRD(VUSB, "Enter: ep->addr=0x%x, &ude_ep=0x%p", ep->addr, &ude_ep);
	WdfIoQueueStart(ep->queue);
	TRD(VUSB, "Leave");
}

static EVT_WDF_IO_QUEUE_STATE queuePurgeComplete;

static VOID
ep_purge(_In_ UDECXUSBENDPOINT ude_ep)
{
	pctx_ep_t	ep = TO_EP(ude_ep);

	TRD(VUSB, "Enter: ep->addr=0x%x, &ude_ep=0x%p", ep->addr, &ude_ep);

	WdfIoQueuePurge(ep->queue, queuePurgeComplete, (WDFCONTEXT)ude_ep);

	TRD(VUSB, "Leave");
}

static VOID
queuePurgeComplete(WDFQUEUE Queue, WDFCONTEXT Context)
{
	UNREFERENCED_PARAMETER(Queue);
	UDECXUSBENDPOINT ude_ep = (UDECXUSBENDPOINT)Context;

	TRD(VUSB, "Enter: &ude_ep=0x%p", &ude_ep);
	UdecxUsbEndpointPurgeComplete(ude_ep);
	TRD(VUSB, "Leave");
}

static VOID
ep_reset(_In_ UDECXUSBENDPOINT ep, _In_ WDFREQUEST req)
{
	UNREFERENCED_PARAMETER(ep);
	UNREFERENCED_PARAMETER(req);

	TRE(VUSB, "Enter");
}

static void
setup_ep_from_dscr(pctx_ep_t ep, PUSB_ENDPOINT_DESCRIPTOR dscr_ep)
{
	if (dscr_ep == NULL) {
		ep->type = USB_ENDPOINT_TYPE_CONTROL;
		ep->addr = USB_DEFAULT_DEVICE_ADDRESS;
		ep->interval = 0;
	}
	else {
		ep->type = dscr_ep->bmAttributes & USB_ENDPOINT_TYPE_MASK;
		ep->addr = dscr_ep->bEndpointAddress;
		ep->interval = dscr_ep->bInterval;
	}
}

NTSTATUS
add_ep(pctx_vusb_t vusb, PUDECXUSBENDPOINT_INIT *pepinit, PUSB_ENDPOINT_DESCRIPTOR dscr_ep)
{
	pctx_ep_t	ep;
	UDECXUSBENDPOINT	ude_ep;
	UDECX_USB_ENDPOINT_CALLBACKS	callbacks;
	WDFQUEUE	queue;
	UCHAR		ep_addr;
	WDF_OBJECT_ATTRIBUTES       attrs;
	NTSTATUS	status;

	ep_addr = dscr_ep ? dscr_ep->bEndpointAddress : USB_DEFAULT_DEVICE_ADDRESS;
	TRD(VUSB, "Enter: ep_addr=0x%x", ep_addr);
	UdecxUsbEndpointInitSetEndpointAddress(*pepinit, ep_addr);

	UDECX_USB_ENDPOINT_CALLBACKS_INIT(&callbacks, ep_reset);
	if (!vusb->is_simple_ep_alloc) {
		/*
		 * FIXME: A simple vusb stops working after a purge routine is called.
		 * The exact reason is unknown.
		 */
		callbacks.EvtUsbEndpointStart = ep_start;
		callbacks.EvtUsbEndpointPurge = ep_purge;
	}
	UdecxUsbEndpointInitSetCallbacks(*pepinit, &callbacks);

	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, ctx_ep_t);
	attrs.ParentObject = vusb->ude_usbdev;
	status = UdecxUsbEndpointCreate(pepinit, &attrs, &ude_ep);
	if (NT_ERROR(status)) {
		TRE(VUSB, "failed to create endpoint: %!STATUS!", status);
		return status;
	}

	ep = TO_EP(ude_ep);
	ep->vusb = vusb;
	ep->ude_ep = ude_ep;
	setup_ep_from_dscr(ep, dscr_ep);

	queue = create_queue_ep(ep);
	if (queue == NULL) {
		WdfObjectDelete(ude_ep);
		TRE(VUSB, "Leave: STATUS_UNSUCCESSFUL");
		return STATUS_UNSUCCESSFUL;
	}
	UdecxUsbEndpointSetWdfIoQueue(ude_ep, queue);

	ep->queue = queue;
	if (dscr_ep == NULL) {
		vusb->ep_default = ep;
	}
	TRD(VUSB, "Leave - &ude_ep=0x%p", &ude_ep);
	return STATUS_SUCCESS;
}

static NTSTATUS
default_ep_add(_In_ UDECXUSBDEVICE udev, _In_ PUDECXUSBENDPOINT_INIT epinit)
{
	pctx_vusb_t	vusb = TO_VUSB(udev);
	NTSTATUS	status;

	TRD(VUSB, "Enter");

	status = add_ep(vusb, &epinit, NULL);

	TRD(VUSB, "Leave: %!STATUS!", status);

	return status;
}

static NTSTATUS
ep_add(_In_ UDECXUSBDEVICE udev, _In_ PUDECX_USB_ENDPOINT_INIT_AND_METADATA epcreate)
{
	pctx_vusb_t	vusb = TO_VUSB(udev);
	NTSTATUS	status;

	TRD(VUSB, "Enter: >bEndpointAddress=0x%x, bInterval: 0x%x",
		epcreate->EndpointDescriptor->bEndpointAddress,
		(ULONG)epcreate->EndpointDescriptor->bInterval);

	status = add_ep(vusb, &epcreate->UdecxUsbEndpointInit, epcreate->EndpointDescriptor);

	TRD(VUSB, "Leave: %!STATUS!", status);

	return status;
}

static NTSTATUS
release_ep(PUDECX_ENDPOINTS_CONFIGURE_PARAMS params)
{
	TRD(VUSB, "Enter: ReleasedEndpointsCount=%d", params->ReleasedEndpointsCount);

	for (ULONG i = 0; i < params->ReleasedEndpointsCount; i++) {
		pctx_ep_t	ep = TO_EP(params->ReleasedEndpoints[i]);
		WdfIoQueuePurgeSynchronously(ep->queue);
		TRD(VUSB, "Released ep->addr=0x%x!", ep->addr);
	}
	return STATUS_SUCCESS;
}

static VOID
ep_configure(_In_ UDECXUSBDEVICE udev, _In_ WDFREQUEST req, _In_ PUDECX_ENDPOINTS_CONFIGURE_PARAMS params)
{
	pctx_vusb_t	vusb = TO_VUSB(udev);
	NTSTATUS	status = STATUS_UNSUCCESSFUL;

	TRD(VUSB, "Enter: %!epconf!", params->ConfigureType);

	status = release_ep(params);
	if ((params->ConfigureType == UdecxEndpointsConfigureTypeEndpointsReleasedOnly) || (vusb->invalid == TRUE)) {
		WdfRequestComplete(req, status);
		TRD(VUSB, "Leave: %!STATUS!", status);
		return;
	}

	switch (params->ConfigureType) {
	case UdecxEndpointsConfigureTypeDeviceInitialize:
		/* FIXME: UDE framework seems to not call SET CONFIGURATION if a USB has multiple interfaces.
		 * This enforces the device to be set with the first configuration.
		 */
		status = submit_req_select(vusb->ep_default, req, 1, vusb->default_conf_value, 0, 0);
		TRD(VUSB, "trying to SET CONFIGURATION: %u", (ULONG)vusb->default_conf_value);
		break;
	case UdecxEndpointsConfigureTypeDeviceConfigurationChange:
		status = submit_req_select(vusb->ep_default, req, 1, params->NewConfigurationValue, 0, 0);
		break;
	case UdecxEndpointsConfigureTypeInterfaceSettingChange:
		status = submit_req_select(vusb->ep_default, req, 0, 0, params->InterfaceNumber, params->NewInterfaceSetting);
		break;
	default:
		TRE(VUSB, "unhandled configure type: %!epconf!", params->ConfigureType);
		break;
	}

	if (status != STATUS_PENDING)
		WdfRequestComplete(req, status);
	TRD(VUSB, "Leave: %!STATUS!", status);
}

VOID
setup_ep_callbacks(PUDECX_USB_DEVICE_STATE_CHANGE_CALLBACKS pcallbacks)
{
	pcallbacks->EvtUsbDeviceDefaultEndpointAdd = default_ep_add;
	pcallbacks->EvtUsbDeviceEndpointAdd = ep_add;
	pcallbacks->EvtUsbDeviceEndpointsConfigure = ep_configure;
}
