# boot.py -- run on boot-up
# can run arbitrary Python, but best to keep it minimal

import pyb

pyb.country('DE')  # ISO 3166-1 Alpha-2 code, eg US, GB, DE, AU
pyb.main('main.py')  # main script to run after this one

HID_PACKET_SIZE = 64
HID_FIDO_ReportDesc = bytes((
    0x06, 0xd0, 0xf1,  # USAGE_PAGE (FIDO Alliance)
    0x09, 0x01,        # USAGE (Keyboard)
    0xa1, 0x01,        # COLLECTION (Application)

    0x09, 0x20,        # USAGE (Input Report Data)
    0x15, 0x00,        # LOGICAL_MINIMUM (0)
    0x26, 0xff, 0x00,  # LOGICAL_MAXIMUM (255)
    0x75, 0x08,        # REPORT_SIZE (8)
    0x95, HID_PACKET_SIZE,  # REPORT_COUNT (64)
    0x81, 0x02,        # INPUT (Data,Var,Abs)
    0x09, 0x21,        # USAGE(Output Report Data)
    0x15, 0x00,        # LOGICAL_MINIMUM (0)
    0x26, 0xff, 0x00,  # LOGICAL_MAXIMUM (255)
    0x75, 0x08,        # REPORT_SIZE (8)
    0x95, HID_PACKET_SIZE,  # REPORT_COUNT (64)
    0x91, 0x02,        # OUTPUT (Data,Var,Abs)

    0xc0                # END_COLLECTION
))

pyb.usb_mode("VCP+HID",
             port=-1,
             vid=0xaffe, pid=0x7b01, hid=(0, 0, 64, 5, HID_FIDO_ReportDesc))
# pyb.usb_mode('VCP+MSC') # act as a serial and a storage device
# pyb.usb_mode('VCP+HID') # act as a serial device and a mouse
