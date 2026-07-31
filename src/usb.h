/*
 * usb.h
 *
 * Copyright (C) 2009 Hector Martin <hector@marcansoft.com>
 * Copyright (C) 2009 Nikias Bassen <nikias@gmx.li>
 * Copyright (C) 2009 Martin Szulecki <opensuse@sukimashita.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 or version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef USB_H
#define USB_H

#include <stdint.h>
#include "utils.h"

#define INTERFACE_CLASS 255
#define INTERFACE_SUBCLASS 254
#define INTERFACE_PROTOCOL 2

// libusb fragments packets larger than this (usbfs limitation)
// on input, this creates race conditions and other issues
#define USB_MRU 16384

// max transmission packet size
//
// Upstream uses 3 * 16384 to suit libusb's fragmentation. The QEMU transport
// cannot express a transaction larger than 16384 (the wire header's length is
// an int16_t), so anything above this has to be sent as several transactions -
// and the device model treats each one as a completed transfer, raising
// XferCompl and disabling the endpoint even when the guest's armed transfer is
// only partly filled. The guest's mux driver then reassembles from truncated
// transfers and the stream desynchronises. Capping the MTU keeps every mux
// packet inside a single transaction; device.c derives conn->max_payload from
// this, so it bounds the whole TX path.
#define USB_MTU 16384

#define USB_PACKET_SIZE 512

#define VID_APPLE 0x5ac
#define PID_RANGE_LOW 0x1290
#define PID_RANGE_MAX 0x12af
#define PID_APPLE_T2_COPROCESSOR 0x8600
#define PID_APPLE_SILICON_RESTORE_LOW 0x1901
#define PID_APPLE_SILICON_RESTORE_MAX 0x1905

#define ENV_DEVICE_MODE "USBMUXD_DEFAULT_DEVICE_MODE"
#define APPLE_VEND_SPECIFIC_GET_MODE 0x45
#define APPLE_VEND_SPECIFIC_SET_MODE 0x52

struct usb_device;

int usb_init(void);
void usb_shutdown(void);
const char *usb_get_serial(struct usb_device *dev);
uint32_t usb_get_location(struct usb_device *dev);
uint16_t usb_get_pid(struct usb_device *dev);
uint64_t usb_get_speed(struct usb_device *dev);
void usb_get_fds(struct fdlist *list);
int usb_get_timeout(void);
int usb_send(struct usb_device *dev, const unsigned char *buf, int length);
int usb_discover(void);
void usb_autodiscover(int enable);
int usb_process(void);
int usb_process_timeout(int msec);

#endif
