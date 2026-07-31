/*
 * usb-qemu.c
 *
 * usbmuxd USB backend that speaks the QEMU tcp_usb transport used by the
 * iPod touch machine model instead of talking to libusb.
 *
 * QEMU is the TCP client and dials us, so we listen. The protocol is strictly
 * host-driven request/response: we send a 5-byte header (plus payload for OUT),
 * the device answers with the same header (length replaced) plus a payload for
 * IN. A negative response length is a QEMU USB_RET_* code; NAK means "retry"
 * and is the entire flow-control mechanism, since everything NAKs until the
 * guest arms the endpoint.
 *
 * The device model is transfer-oriented, not packet-oriented, and has no
 * notion of a control transfer: SETUP, data and status are three independent
 * endpoint transactions and the guest's own USB stack supplies the
 * descriptors. So we do host-side enumeration here by hand.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 or version 3.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "usb.h"
#include "log.h"
#include "device.h"
#include "utils.h"

/* --- wire format (mirrors hw/arm/ipod_touch_tcp_usb.h) ------------------- */

struct tcp_usb_header {
	uint8_t addr;
	uint8_t ep;
	uint8_t flags;
	int16_t length;
} __attribute__((packed));

#define TU_SETUP    (1 << 0)
#define TU_RESET    (1 << 1)
#define TU_ENUMDONE (1 << 2)

#define USB_DIR_IN  0x80

/* QEMU USB_RET_* codes, arriving as a negative length. */
#define RET_NODEV   (-1)
#define RET_NAK     (-2)
#define RET_STALL   (-3)

/* Our own, distinct from anything QEMU returns. */
#define RET_IO      (-1000)

/* The header length field is an int16_t, so a single transaction cannot carry
 * more than this. USB_MRU (16384) fits comfortably. */
#define QEMU_MAX_XFER 16384

#define DEFAULT_PORT 1235
#define DEFAULT_POLL_MS 3

/* How long to keep retrying a NAKing transaction before giving up. */
#define CTRL_TIMEOUT_MS   15000
#define STATUS_TIMEOUT_MS 500
#define SEND_TIMEOUT_MS   10000

/* Consecutive NAKs after which a partially-filled IN transfer is considered
 * complete. The guest hands us a descriptor in one or more chunks and has no
 * way to say "that was the last one" other than by going quiet. */
#define IN_IDLE_NAKS 30

/* Bulk IN reads to drain per usb_process() call before yielding to the loop. */
#define RX_BURST 8

struct usb_device {
	int fd;
	int alive;
	char serial[256];
	uint8_t address;
	uint8_t interface, altsetting, ep_in, ep_out;
	uint16_t pid;
	uint64_t speed;
	int wMaxPacketSize;
	unsigned char rxbuf[USB_MRU];
};

static int listen_fd = -1;
static int pending_fd = -1;          /* accepted, enumeration not started */
static uint64_t pending_ready_ms;    /* when to start driving RESET */
static int enum_attempts;            /* enumeration tries on this connection */
static struct usb_device *the_device;
static int autodiscover = 1;
static int poll_ms = DEFAULT_POLL_MS;

/*
 * How long the guest gets to become ready. QEMU dials us as soon as the machine
 * starts but only answers a USB reset once iOS has programmed the OTG core,
 * which takes a variable ~100 s of boot. QEMU will not redial unless the core
 * resets, so giving up on the connection after one failed attempt strands the
 * device until the emulator is restarted - retry on the same socket instead.
 */
#define ENUM_MAX_ATTEMPTS 12
#define ENUM_RETRY_MS 15000

static uint64_t now_ms(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void sleep_ms(int ms)
{
	struct timespec ts;
	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (long)(ms % 1000) * 1000000L;
	nanosleep(&ts, NULL);
}

static const char *ret_name(int r)
{
	switch (r) {
	case RET_NODEV: return "NODEV";
	case RET_NAK:   return "NAK";
	case RET_STALL: return "STALL";
	case RET_IO:    return "IO";
	default:        return "?";
	}
}

/* --- raw socket helpers -------------------------------------------------- */

static int write_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	while (len) {
		ssize_t r = write(fd, p, len);
		if (r > 0) {
			p += r;
			len -= r;
			continue;
		}
		if (r < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		return -1;
	}
	return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
	char *p = buf;
	while (len) {
		ssize_t r = read(fd, p, len);
		if (r > 0) {
			p += r;
			len -= r;
			continue;
		}
		if (r < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		return -1;
	}
	return 0;
}

/*
 * One request/response round trip.
 *
 * For an OUT endpoint, out_data supplies `length` bytes. For an IN endpoint,
 * `length` is the maximum we are willing to accept and in_data receives what
 * the device actually returns. Returns the device's length field, which may be
 * a negative USB_RET_* code, or RET_IO if the socket died.
 */
static int qemu_xfer(int fd, uint8_t ep, uint8_t flags, int length,
                     const void *out_data, void *in_data, uint8_t *ret_addr)
{
	struct tcp_usb_header hdr;

	if (length > QEMU_MAX_XFER)
		length = QEMU_MAX_XFER;

	hdr.addr = 0;
	hdr.ep = ep;
	hdr.flags = flags;
	hdr.length = (int16_t)length;

	if (write_all(fd, &hdr, sizeof(hdr)) < 0)
		return RET_IO;
	if (!(ep & USB_DIR_IN) && length > 0 && out_data) {
		if (write_all(fd, out_data, length) < 0)
			return RET_IO;
	}

	if (read_all(fd, &hdr, sizeof(hdr)) < 0)
		return RET_IO;
	if (ret_addr)
		*ret_addr = hdr.addr;

	if ((hdr.ep & USB_DIR_IN) && hdr.length > 0) {
		int n = hdr.length;
		if (n > length)   /* the device must never overrun what we asked for */
			n = length;
		if (in_data) {
			if (read_all(fd, in_data, n) < 0)
				return RET_IO;
		} else {
			char sink[512];
			int left = n;
			while (left > 0) {
				int chunk = left > (int)sizeof(sink) ? (int)sizeof(sink) : left;
				if (read_all(fd, sink, chunk) < 0)
					return RET_IO;
				left -= chunk;
			}
		}
		return n;
	}

	/* An OUT can never be acknowledged for more than was submitted; the device
	 * model clamps amtDone to the request length. If it ever happens, believing
	 * it would advance our offset past data the guest never received. */
	if (!(ep & USB_DIR_IN) && hdr.length > length) {
		usbmuxd_log(LL_ERROR,
		            "PROTOCOL: ep 0x%02x acknowledged %d bytes for a %d byte OUT; clamping",
		            ep, (int)hdr.length, length);
		return length;
	}

	return hdr.length;
}

/* --- control transfers --------------------------------------------------- */

/* Deliver the 8-byte setup packet as a SETUP-flagged OUT on EP0. */
static int send_setup(int fd, const unsigned char *setup, uint8_t *addr)
{
	uint64_t deadline = now_ms() + CTRL_TIMEOUT_MS;
	for (;;) {
		int r = qemu_xfer(fd, 0x00, TU_SETUP, 8, setup, NULL, addr);
		if (r >= 0)
			return 0;
		if (r == RET_IO || r == RET_NODEV)
			return -1;
		if (now_ms() > deadline) {
			usbmuxd_log(LL_ERROR, "SETUP never accepted (%s)", ret_name(r));
			return -1;
		}
		sleep_ms(1);
	}
}

/*
 * Best-effort status stage. The device model does not track control transfer
 * phases, so if the guest never arms the opposite-direction endpoint the
 * status transaction simply NAKs forever. That is not fatal - the next SETUP
 * resets the guest's own state machine - so we time out quietly.
 */
static void status_stage(int fd, int in)
{
	uint64_t deadline = now_ms() + STATUS_TIMEOUT_MS;
	for (;;) {
		int r = qemu_xfer(fd, in ? USB_DIR_IN : 0x00, 0, 0, NULL, NULL, NULL);
		if (r >= 0 || r == RET_IO || r == RET_NODEV)
			return;
		if (now_ms() > deadline)
			return;
		sleep_ms(1);
	}
}

static void fill_setup(unsigned char *s, uint8_t bmRequestType, uint8_t bRequest,
                       uint16_t wValue, uint16_t wIndex, uint16_t wLength)
{
	s[0] = bmRequestType;
	s[1] = bRequest;
	s[2] = wValue & 0xff;
	s[3] = wValue >> 8;
	s[4] = wIndex & 0xff;
	s[5] = wIndex >> 8;
	s[6] = wLength & 0xff;
	s[7] = wLength >> 8;
}

/* Device-to-host control transfer. Returns bytes read, or -1. */
static int ctrl_in(int fd, uint8_t bmRequestType, uint8_t bRequest,
                   uint16_t wValue, uint16_t wIndex,
                   unsigned char *buf, uint16_t wLength)
{
	unsigned char setup[8];
	uint64_t deadline;
	int total = 0, naks = 0;

	fill_setup(setup, bmRequestType | 0x80, bRequest, wValue, wIndex, wLength);
	if (send_setup(fd, setup, NULL) < 0)
		return -1;

	deadline = now_ms() + CTRL_TIMEOUT_MS;
	while (total < wLength) {
		int r = qemu_xfer(fd, USB_DIR_IN, 0, wLength - total, NULL, buf + total, NULL);
		if (r > 0) {
			total += r;
			naks = 0;
			continue;
		}
		if (r == 0)          /* short/zero packet terminates the transfer */
			break;
		if (r == RET_IO || r == RET_NODEV || r == RET_STALL) {
			if (total > 0)
				break;
			usbmuxd_log(LL_DEBUG, "control IN req 0x%02x failed: %s", bRequest, ret_name(r));
			return -1;
		}
		/* NAK */
		if (total > 0 && ++naks > IN_IDLE_NAKS)
			break;
		if (now_ms() > deadline) {
			if (total > 0)
				break;
			usbmuxd_log(LL_ERROR, "control IN req 0x%02x timed out", bRequest);
			return -1;
		}
		sleep_ms(1);
	}

	status_stage(fd, 0);
	return total;
}

/* Host-to-device control transfer with no data stage. */
static int ctrl_out(int fd, uint8_t bmRequestType, uint8_t bRequest,
                    uint16_t wValue, uint16_t wIndex, uint8_t *addr)
{
	unsigned char setup[8];

	fill_setup(setup, bmRequestType & 0x7f, bRequest, wValue, wIndex, 0);
	if (send_setup(fd, setup, addr) < 0)
		return -1;
	status_stage(fd, 1);
	return 0;
}

/* --- enumeration --------------------------------------------------------- */

static void decode_string(const unsigned char *data, int len, char *out, size_t outsz)
{
	size_t di = 0;
	int si;
	if (len < 2)
		len = 0;
	for (si = 2; si < len && si < data[0] && di < outsz - 1; si += 2) {
		if ((data[si] & 0x80) || data[si + 1])
			out[di++] = '?';
		else if (data[si] == '\0')
			break;
		else
			out[di++] = data[si];
	}
	out[di] = '\0';
}

/*
 * Walk a configuration descriptor tree looking for the AppleUSBMux interface
 * (class 255, subclass 254, protocol 2) with one bulk IN and one bulk OUT.
 */
static int find_mux_interface(const unsigned char *cfg, int len, struct usb_device *dev)
{
	int i = 0;
	int in_match = 0;
	uint8_t intf = 0, alt = 0, ep_in = 0, ep_out = 0;

	while (i + 1 < len) {
		int dlen = cfg[i];
		int dtype = cfg[i + 1];
		if (dlen < 2 || i + dlen > len)
			break;

		if (dtype == 0x04 && dlen >= 9) {          /* INTERFACE */
			if (in_match && ep_in && ep_out)
				goto done;
			in_match = (cfg[i + 5] == INTERFACE_CLASS &&
			            cfg[i + 6] == INTERFACE_SUBCLASS &&
			            cfg[i + 7] == INTERFACE_PROTOCOL);
			intf = cfg[i + 2];
			alt = cfg[i + 3];
			ep_in = ep_out = 0;
		} else if (dtype == 0x05 && dlen >= 7 && in_match) {   /* ENDPOINT */
			uint8_t addr = cfg[i + 2];
			uint8_t attr = cfg[i + 3] & 0x03;
			if (attr == 0x02) {                     /* bulk */
				if (addr & 0x80)
					ep_in = addr;
				else
					ep_out = addr;
			}
		}
		i += dlen;
	}

done:
	if (!in_match || !ep_in || !ep_out)
		return -1;

	dev->interface = intf;
	dev->altsetting = alt;
	dev->ep_in = ep_in;
	dev->ep_out = ep_out;
	return 0;
}

/*
 * Drive the link from cable-plug to a configured device with a known serial.
 * Runs inline; the daemon's main loop is blocked while it happens, which is
 * acceptable because nothing else can make progress until there is a device.
 */
static struct usb_device *enumerate(int fd)
{
	unsigned char devdesc[18];
	unsigned char cfgbuf[1024];
	unsigned char strbuf[256];
	struct usb_device *dev;
	uint8_t addr = 0;
	uint16_t langid = 0x0409;
	uint8_t iserial;
	int r, n, cfg_index, chosen = -1;

	usbmuxd_log(LL_NOTICE, "Driving USB reset");
	if (qemu_xfer(fd, 0x00, TU_RESET, 0, NULL, NULL, NULL) == RET_IO)
		return NULL;
	sleep_ms(500);

	usbmuxd_log(LL_NOTICE, "Signalling enumeration done");
	if (qemu_xfer(fd, 0x00, TU_ENUMDONE, 0, NULL, NULL, NULL) == RET_IO)
		return NULL;
	sleep_ms(500);

	n = ctrl_in(fd, 0x80, 0x06, (0x01 << 8) | 0, 0, devdesc, sizeof(devdesc));
	if (n < 18) {
		usbmuxd_log(LL_ERROR, "Could not read the device descriptor (%d bytes)", n);
		return NULL;
	}
	if (devdesc[1] != 0x01) {
		usbmuxd_log(LL_ERROR, "Response is not a DEVICE descriptor (type 0x%02x)", devdesc[1]);
		return NULL;
	}

	dev = calloc(1, sizeof(*dev));
	dev->fd = fd;
	dev->alive = 1;
	dev->speed = 480000000;
	dev->pid = devdesc[10] | (devdesc[11] << 8);
	dev->wMaxPacketSize = devdesc[7] ? devdesc[7] : 64;
	iserial = devdesc[16];

	usbmuxd_log(LL_NOTICE, "Device %04x:%04x, bcdUSB %x.%02x, %d configuration(s)",
	            devdesc[8] | (devdesc[9] << 8), dev->pid,
	            devdesc[3], devdesc[2], devdesc[17]);

	if (ctrl_out(fd, 0x00, 0x05, 1, 0, NULL) < 0) {
		usbmuxd_log(LL_ERROR, "SET_ADDRESS failed");
		goto fail;
	}
	/* The device reports its DCFG address back in every reply header, which is
	 * how we learn the guest actually programmed it. */
	{
		uint64_t deadline = now_ms() + 2000;
		do {
			qemu_xfer(fd, USB_DIR_IN, 0, 0, NULL, NULL, &addr);
			if (addr == 1)
				break;
			sleep_ms(10);
		} while (now_ms() < deadline);
	}
	dev->address = addr;
	usbmuxd_log(LL_NOTICE, "Device address is %d", addr);

	/* Configuration descriptors: 9 bytes for wTotalLength, then the tree. */
	for (cfg_index = 0; cfg_index < devdesc[17]; cfg_index++) {
		int total;
		n = ctrl_in(fd, 0x80, 0x06, (0x02 << 8) | cfg_index, 0, cfgbuf, 9);
		if (n < 9) {
			usbmuxd_log(LL_WARNING, "Short header for configuration %d (%d)", cfg_index, n);
			continue;
		}
		total = cfgbuf[2] | (cfgbuf[3] << 8);
		if (total < 9 || total > (int)sizeof(cfgbuf)) {
			usbmuxd_log(LL_WARNING, "Configuration %d has implausible wTotalLength %d", cfg_index, total);
			continue;
		}
		n = ctrl_in(fd, 0x80, 0x06, (0x02 << 8) | cfg_index, 0, cfgbuf, total);
		if (n < total) {
			usbmuxd_log(LL_WARNING, "Short configuration %d (%d of %d)", cfg_index, n, total);
			continue;
		}
		if (find_mux_interface(cfgbuf, n, dev) == 0) {
			chosen = cfgbuf[5];   /* bConfigurationValue */
			usbmuxd_log(LL_NOTICE,
			            "Found the mux interface in configuration %d (value %d): "
			            "interface %d alt %d, endpoints in 0x%02x out 0x%02x",
			            cfg_index, chosen, dev->interface, dev->altsetting,
			            dev->ep_in, dev->ep_out);
			break;
		}
	}

	if (chosen < 0) {
		usbmuxd_log(LL_ERROR, "No AppleUSBMux interface (%d/%d/%d) in any configuration",
		            INTERFACE_CLASS, INTERFACE_SUBCLASS, INTERFACE_PROTOCOL);
		goto fail;
	}

	if (ctrl_out(fd, 0x00, 0x09, chosen, 0, NULL) < 0) {
		usbmuxd_log(LL_ERROR, "SET_CONFIGURATION %d failed", chosen);
		goto fail;
	}
	if (dev->altsetting != 0 &&
	    ctrl_out(fd, 0x01, 0x0b, dev->altsetting, dev->interface, NULL) < 0) {
		usbmuxd_log(LL_WARNING, "SET_INTERFACE %d/%d failed, continuing",
		            dev->interface, dev->altsetting);
	}

	/* Index 0 is the list of supported language IDs. */
	n = ctrl_in(fd, 0x80, 0x06, (0x03 << 8) | 0, 0, strbuf, sizeof(strbuf));
	if (n >= 4)
		langid = strbuf[2] | (strbuf[3] << 8);
	usbmuxd_log(LL_INFO, "Using language ID 0x%04x", langid);

	n = ctrl_in(fd, 0x80, 0x06, (0x03 << 8) | iserial, langid, strbuf, sizeof(strbuf));
	if (n < 4) {
		usbmuxd_log(LL_ERROR, "Could not read the serial number string (%d)", n);
		goto fail;
	}
	decode_string(strbuf, n, dev->serial, sizeof(dev->serial));

	/* New style UDIDs carry a hyphen between the first 8 and following 16. */
	r = strlen(dev->serial);
	if (r == 24) {
		memmove(&dev->serial[9], &dev->serial[8], 16);
		dev->serial[8] = '-';
		dev->serial[25] = '\0';
	}

	if (!dev->serial[0]) {
		usbmuxd_log(LL_ERROR, "Device reported an empty serial number");
		goto fail;
	}
	usbmuxd_log(LL_NOTICE, "Serial number is '%s'", dev->serial);
	return dev;

fail:
	free(dev);
	return NULL;
}

/* --- backend interface --------------------------------------------------- */

int usb_init(void)
{
	const char *spec = getenv("USBMUXD_QEMU_ADDR");
	const char *pollspec = getenv("USBMUXD_QEMU_POLL_MS");
	char host[128] = "127.0.0.1";
	int port = DEFAULT_PORT;
	struct sockaddr_in sa;
	int one = 1;

	if (spec && *spec) {
		const char *colon = strrchr(spec, ':');
		if (colon) {
			size_t hl = colon - spec;
			if (hl >= sizeof(host))
				hl = sizeof(host) - 1;
			memcpy(host, spec, hl);
			host[hl] = '\0';
			port = atoi(colon + 1);
		} else {
			port = atoi(spec);
		}
		if (port <= 0 || port > 65535)
			port = DEFAULT_PORT;
	}
	if (pollspec && atoi(pollspec) > 0)
		poll_ms = atoi(pollspec);

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		usbmuxd_log(LL_FATAL, "Could not create the QEMU listening socket: %s", strerror(errno));
		return -1;
	}
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	fcntl(listen_fd, F_SETFL, fcntl(listen_fd, F_GETFL, 0) | O_NONBLOCK);

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (inet_pton(AF_INET, host, &sa.sin_addr) != 1)
		sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(listen_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		usbmuxd_log(LL_FATAL, "Could not bind %s:%d: %s", host, port, strerror(errno));
		close(listen_fd);
		listen_fd = -1;
		return -1;
	}
	if (listen(listen_fd, 1) < 0) {
		usbmuxd_log(LL_FATAL, "Could not listen on %s:%d: %s", host, port, strerror(errno));
		close(listen_fd);
		listen_fd = -1;
		return -1;
	}

	usbmuxd_log(LL_NOTICE, "QEMU USB backend listening on %s:%d (poll %d ms)", host, port, poll_ms);
	return 0;
}

void usb_shutdown(void)
{
	if (the_device) {
		device_remove(the_device);
		close(the_device->fd);
		free(the_device);
		the_device = NULL;
	}
	if (pending_fd >= 0) {
		close(pending_fd);
		pending_fd = -1;
	}
	if (listen_fd >= 0) {
		close(listen_fd);
		listen_fd = -1;
	}
}

const char *usb_get_serial(struct usb_device *dev)
{
	return dev->alive ? dev->serial : NULL;
}

uint32_t usb_get_location(struct usb_device *dev)
{
	return 0x00010001;
}

uint16_t usb_get_pid(struct usb_device *dev)
{
	return dev->pid;
}

uint64_t usb_get_speed(struct usb_device *dev)
{
	return dev->speed;
}

void usb_get_fds(struct fdlist *list)
{
	if (listen_fd >= 0)
		fdlist_add(list, FD_USB, listen_fd, POLLIN);
	/* The device never speaks unprompted, so this only ever fires on EOF -
	 * which is exactly the event we want to notice promptly. */
	if (the_device && the_device->alive)
		fdlist_add(list, FD_USB, the_device->fd, POLLIN);
	else if (pending_fd >= 0)
		fdlist_add(list, FD_USB, pending_fd, POLLIN);
}

int usb_get_timeout(void)
{
	if (the_device && the_device->alive)
		return poll_ms;
	if (pending_fd >= 0)
		return 50;
	return 1000;
}

int usb_send(struct usb_device *dev, const unsigned char *buf, int length)
{
	static unsigned call_seq;
	unsigned seq = ++call_seq;
	int sent = 0, txn = 0, naks = 0, accepted = 0;
	uint64_t deadline = now_ms() + SEND_TIMEOUT_MS;

	/*
	 * Buffer ownership follows the libusb backend: it transfers to us only on
	 * success, and device.c's send_packet frees it itself on failure. Freeing
	 * it on an error path here is a double free.
	 */
	if (!dev->alive)
		return -1;

	usbmuxd_log(LL_NOTICE, "OUT#%u begin: %d bytes to ep 0x%02x", seq, length, dev->ep_out);

	while (sent < length) {
		int chunk = length - sent;
		int r;
		if (chunk > QEMU_MAX_XFER)
			chunk = QEMU_MAX_XFER;

		r = qemu_xfer(dev->fd, dev->ep_out, 0, chunk, buf + sent, NULL, NULL);
		txn++;
		if (r > 0) {
			usbmuxd_log(LL_NOTICE,
			            "OUT#%u txn %d: offset %d submitted %d accepted %d -> offset %d (after %d NAKs)",
			            seq, txn, sent, chunk, r, sent + r, naks);
			sent += r;
			accepted++;
			naks = 0;
			deadline = now_ms() + SEND_TIMEOUT_MS;
			continue;
		}
		if (r == 0) {
			usbmuxd_log(LL_WARNING,
			            "OUT#%u txn %d: offset %d submitted %d accepted 0 (endpoint armed with a zero-length transfer)",
			            seq, txn, sent, chunk);
			naks++;
			sleep_ms(1);
			continue;
		}
		if (r == RET_IO || r == RET_NODEV || r == RET_STALL) {
			usbmuxd_log(LL_ERROR, "OUT#%u txn %d: failed at offset %d of %d: %s",
			            seq, txn, sent, length, ret_name(r));
			dev->alive = 0;
			return -1;
		}
		naks++;
		if (now_ms() > deadline) {
			usbmuxd_log(LL_ERROR, "OUT#%u txn %d: stalled at offset %d of %d after %d NAKs",
			            seq, txn, sent, length, naks);
			dev->alive = 0;
			return -1;
		}
		sleep_ms(1);
	}

	/* "accepted" is what answers "was this split?" - txn also counts NAK
	 * retries, which are just flow control and say nothing about framing. */
	usbmuxd_log(LL_NOTICE, "OUT#%u done: %d bytes, %s (%d accepted transfer(s), %d round trip(s))",
	            seq, sent, accepted > 1 ? "SPLIT" : "whole", accepted, txn);
	free((void *)buf);
	return 0;
}

int usb_discover(void)
{
	return the_device ? 1 : 0;
}

void usb_autodiscover(int enable)
{
	usbmuxd_log(LL_DEBUG, "usb polling enable: %d", enable);
	autodiscover = enable;
}

static void accept_pending(void)
{
	struct sockaddr_in sa;
	socklen_t sl = sizeof(sa);
	int fd, one = 1;
	struct timeval tv;
	const char *delayspec;
	int delay;

	if (listen_fd < 0)
		return;

	fd = accept(listen_fd, (struct sockaddr *)&sa, &sl);
	if (fd < 0)
		return;

	if (!autodiscover || the_device || pending_fd >= 0) {
		usbmuxd_log(LL_WARNING, "Rejecting a second QEMU connection");
		close(fd);
		return;
	}

	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	/* Blocking with a timeout: every transaction is a round trip and a wedged
	 * QEMU must not freeze the daemon forever. */
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	delayspec = getenv("USBMUXD_QEMU_DELAY");
	delay = delayspec ? atoi(delayspec) : 0;
	if (delay < 0)
		delay = 0;

	pending_fd = fd;
	pending_ready_ms = now_ms() + (uint64_t)delay * 1000;
	enum_attempts = 0;
	usbmuxd_log(LL_NOTICE, "QEMU device connected from %s; starting enumeration in %d s",
	            inet_ntoa(sa.sin_addr), delay);
}

static void reap(void)
{
	struct usb_device *dev = the_device;
	if (!dev || dev->alive)
		return;
	usbmuxd_log(LL_NOTICE, "Device went away");
	the_device = NULL;
	device_remove(dev);
	close(dev->fd);
	free(dev);
}

int usb_process(void)
{
	struct usb_device *dev;
	int i;

	accept_pending();

	if (pending_fd >= 0 && now_ms() >= pending_ready_ms) {
		int fd = pending_fd;
		pending_fd = -1;
		dev = enumerate(fd);
		if (!dev) {
			if (++enum_attempts < ENUM_MAX_ATTEMPTS) {
				usbmuxd_log(LL_WARNING,
				            "Enumeration attempt %d failed; the guest is probably still "
				            "booting, retrying in %d s",
				            enum_attempts, ENUM_RETRY_MS / 1000);
				pending_fd = fd;
				pending_ready_ms = now_ms() + ENUM_RETRY_MS;
			} else {
				usbmuxd_log(LL_ERROR,
				            "Enumeration failed %d times; dropping the connection",
				            enum_attempts);
				close(fd);
			}
		} else {
			the_device = dev;
			if (device_add(dev) < 0) {
				usbmuxd_log(LL_ERROR, "device_add failed");
				the_device = NULL;
				close(fd);
				free(dev);
			}
		}
	}

	dev = the_device;
	if (dev && dev->alive) {
		for (i = 0; i < RX_BURST; i++) {
			int r = qemu_xfer(dev->fd, dev->ep_in, 0, USB_MRU, NULL, dev->rxbuf, NULL);
			if (r > 0) {
				static unsigned in_seq;
				usbmuxd_log(LL_NOTICE, "IN#%u: %d bytes from ep 0x%02x (requested %d)",
				            ++in_seq, r, dev->ep_in, USB_MRU);
				device_data_input(dev, dev->rxbuf, r);
				if (!the_device || !the_device->alive)
					break;
				continue;
			}
			if (r == RET_IO || r == RET_NODEV || r == RET_STALL) {
				if (r != RET_STALL)
					usbmuxd_log(LL_ERROR, "Bulk IN failed: %s", ret_name(r));
				dev->alive = 0;
			}
			break;   /* NAK: nothing queued right now */
		}
	}

	reap();
	return 0;
}

int usb_process_timeout(int msec)
{
	uint64_t deadline = now_ms() + msec;
	while (now_ms() < deadline) {
		if (usb_process() < 0)
			return -1;
		sleep_ms(poll_ms);
	}
	return 0;
}
