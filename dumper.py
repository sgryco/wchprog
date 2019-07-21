#!/usr/bin/python
from __future__ import print_function

import argparse
import struct
import sys
from typing import List

import usb.core
import usb.util
from intelhex import IntelHex

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-d", "--dump", action="store_true", help='dump the flash')
group.add_argument('-f', "--flash", type=str, metavar='HEX', help='flash the provided hex file')
parser.add_argument('-a', '--all', help='dump all the memory (inc. the'
                                        ' bootloader), else only the '
                                        'application code flash',
                    action='store_true', default=False)
parser.add_argument('-s', '--start', action='store_true', default=False,
                    help='start the program after flashing')
parser.add_argument('-v', '--verbose', help='enable debug prints',
                    action='store_true')

scrambleCode = (0x29, 0x52, 0x8C, 0x70)

stats = [0xff, 0xf5, 0x75, 0xe5, 0x02, 0x00, 0xe4, 0x80, 0x22, 0x30, 0x74,
         0x12, 0x82, 0xf0, 0x03, 0x10, 0x0b, 0xfe, 0x60, 0xef, 0x85, 0x70,
         0x2b, 0x05, 0x01, 0x3f, 0xfb, 0xe0, 0x83, 0xc2, 0x24, 0xf8, 0x3b,
         0xfd, 0x95, 0x08, 0x25, 0xeb, 0xe6, 0x90, 0x0e, 0x0d, 0xee, 0x6e,
         0x40, 0xa1, 0x13, 0x0f, 0x0a, 0x09, 0x07, 0x0c, 0xd2, 0xc3, 0x64,
         0xc9, 0xaf, 0x54, 0x04, 0xfc, 0xc0, 0x33, 0x2e, 0x20, 0x06, 0x99,
         0x8e, 0x50, 0x43, 0x94, 0x93, 0x73, 0xed, 0xd8, 0xb4, 0xf9, 0xbb,
         0x8f, 0x8d, 0x8c, 0x79, 0x55, 0x3e, 0x35, 0x2d, 0xe9, 0x65, 0x44,
         0x3c, 0xec, 0xd0, 0xc1, 0xb1, 0xaa, 0x96, 0x89, 0x7f, 0x6f, 0x4c,
         0x38, 0x34, 0x98, 0x86, 0x78, 0x2c, 0x2a, 0x14, 0xdc, 0xcf, 0xa0,
         0x7a, 0x4f, 0x39, 0x1f, 0x11, 0xe3, 0xda, 0xd9, 0xd4, 0xae, 0xac,
         0xa5, 0xa4, 0xa3, 0x9d, 0x8a, 0x84, 0x7b, 0x72, 0x71, 0x5f, 0x45,
         0xf6, 0xf3, 0xe7, 0xdb, 0xce, 0xc6, 0xb9, 0x4e, 0x23, 0x1b, 0x15,
         0xf2, 0xe8, 0xd3, 0xcc, 0xc5, 0xbe, 0xab, 0xa2, 0x9e, 0x92, 0x87,
         0x81, 0x7e, 0x5a, 0x57, 0x53, 0x51, 0x3a, 0x32, 0x29, 0x26, 0x21,
         0x1e, 0x16, 0xfa, 0xf4, 0xf1, 0xe2, 0xe1, 0xdf, 0xde, 0xdd, 0xd5,
         0xc7, 0xb6, 0xb2, 0x9f, 0x9a, 0x88, 0x7d, 0x4d, 0x48, 0x42, 0x36,
         0x31, 0xf7, 0xd7, 0xd1, 0xcd, 0xc8, 0xc4, 0xb8, 0xad, 0xa9, 0xa8,
         0x9c, 0x8b, 0x7c, 0x77, 0x76, 0x6d, 0x69, 0x68, 0x63, 0x62, 0x61,
         0x5e, 0x56, 0x49, 0x3d, 0x2f, 0x28, 0x27, 0x1d, 0x1c, 0x18, 0x17,
         0x19, 0x1A, 0x37, 0x41, 0x46, 0x47, 0x4A, 0x4B, 0x52, 0x58, 0x59,
         0x5B, 0x5C, 0x5D, 0x66, 0x67, 0x6A, 0x6B, 0x6C, 0x91, 0x97, 0x9B,
         0xA6, 0xA7, 0xB0, 0xB3, 0xB5, 0xB7, 0xBA, 0xBC, 0xBD, 0xBF, 0xCA,
         0xCB, 0xD6, 0xEA,]  # type: List[int]


def scramble(l):
    return [v ^ scrambleCode[i % 4] for i, v in enumerate(l)]


def bin_str_of_list(l):
    return ''.join(chr(x) for x in l)


def hex_str(v):
    return ','.join('0x{:02X}'.format(c) for c in v)


class WCHISP:
    def __init__(self, debug=False):
        # find our device
        self.debug = debug
        dev = usb.core.find(idVendor=0x4348, idProduct=0x55e0)
        if dev is None:
            raise ValueError('Device not found')

        dev.set_configuration()
        cfg = dev.get_active_configuration()
        intf = cfg[(0, 0)]

        self.epout = usb.util.find_descriptor(intf, custom_match=lambda
            e: usb.util.endpoint_direction(
            e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
        self.epin = usb.util.find_descriptor(intf, custom_match=lambda
            e: usb.util.endpoint_direction(
            e.bEndpointAddress) == usb.util.ENDPOINT_IN)

    def cmd_verify_v2(self, msg, rlen=64):
        # command formats (depends on command):
        # CMD LEN DATA
        # CMD LEN XX ADDRL ADDRH DATA[LEN]
        # response format
        # CMD XX LEN 0 RESULT DATA[LEN]
        self.writeb(msg)
        b = self.readb(rlen)

        if len(b) < 5:
            raise ValueError('Response too short for cmd 0x{:02X}, len={}'
                             ''.format(msg[0], len(b)))
        if b[0] != ord(msg[0]):
            raise ValueError('Wrong response header 0x{:02X} insteadof '
                             '0x{:02X}'.format(b[0], ord(msg[0])))
        result, dlen, data = b[4], b[2] - 1, b[5:]

        if dlen != len(data):
            raise ValueError('Wrong response data len {} insteadof '
                             '{}'.format(len(data), dlen))
        if self.debug:
            print('[DEBUG] cmd: {}'.format(hex_str(map(ord, msg))))
            print('[DEBUG] result = 0x{:02x} data={}'.format(result,
                                                             hex_str(data)))
        return result, data

    def cmd(self, msg, length=64):
        self.writeb(msg)
        b = self.readb(length)
        if len(b) == 2:
            return struct.unpack('<H', b)[0]
        return b

    def xcmd(self, msg, exp):
        # xmsg = map(lambda x: hex(ord(x))[2:], msg)
        # print ' '.join(xmsg)
        # return 0

        ret = self.cmd(msg)
        if ret != exp:
            xmsg = map(lambda x: hex(ord(x)), msg[0:4])
            raise Exception(
                'cmd[%s] return %d != %d' % (','.join(xmsg), ret, exp))

    def info(self):
        # try bootloader v
        v = self.cmd('\xa2\x13USB DBG CH559 & ISP' + '\0')
        # import ipdb;ipdb.set_trace()
        if type(v) is not int:  # not the int reply expected, trying bootloader v2
            res, data = self.cmd_verify_v2(
                '\xa1\x12\x00\x52\x11MCU ISP & WCH.CN')
            if data[0] != 0x11:
                return 0  # failure
            self.chip_model = res
            print('Chip model: 0x{:02X}'.format(self.chip_model))

            res, data = self.cmd_verify_v2('\xa7\x00\x00\x08')
            assert (res == 0x08)
            # print('cfg 0x08: {}'.format(hexstr(v[6:])))
            print('Bootloader version {}{}.{}{}'.format(*data[1:]))

            # v = self.cmd('\xa7\x00\x00\x07')
            # print('cfg 0x07: {}'.format(hexstr(v[6:])))
            res, data = self.cmd_verify_v2('\xa7\x00\x00\x10')
            assert (res == 0x10)
            print('chip ID: {}'.format(hex_str(data)))
            self.SnSum = sum(data[1:5]) & 0xFF
            print('SnSum = 0x{:02X}'.format(self.SnSum))
            return self.chip_model

        self.cmd('\xbb\x00')
        print(v)
        return v

    def set_key_v2(self):
        # Set the key used to scramble the data over USB
        # [6*4] [9*1] [6*1] [6*6] [6*3] [9*3] [6*5] CHID_ID +[6*4]
        # [24] [9] [6] [36] [18] [27] [30] [24]+CHIP_ID
        data = [0x00] * 0x30
        self.scrambleCodeV2 = data
        data = [d ^ self.SnSum for d in data]
        cmd = '\xa3\x30\x00'
        res, rdata = self.cmd_verify_v2(cmd + bin_str_of_list(data))
        self.scrambleCodeV2[7] += self.chip_model
        sumD = sum(self.scrambleCodeV2) & 0xFF
        assert (res == sumD)

    def flashV2(self, mem):
        ## erase page 0
        print('Erasing flash')
        cmd = '\xa4\x00\x00\x08'
        res, rdata = self.cmd_verify_v2(cmd)
        assert (res == 0x00)  # valid erase address? TODO verify return code

        ## <aa> <len> <x> <addrL> <addrH> <x> <x> <x> <data[len+5]>
        cmd_write = [0xa5, 0, 0, 0, 0, 0, 0, 0]

        if self.debug:
            print('len of hex:', len(mem))
        for addr in range(mem.minaddr(), mem.maxaddr() + 1, 56):
            print('flashing 0x{:04X}: 0x{:02X} 0x{:02X}'.format(
                addr, mem[addr], mem[addr + 1]))
            # len is data + 5, actual packet is data + 5 + 3
            len_data = min(56, mem.maxaddr() + 1 - addr)
            cmd_write[1] = 5 + len_data  # len
            cmd_write[3] = addr & 0xFF
            cmd_write[4] = (addr >> 8) & 0xFF
            data = [mem[a] for a in range(addr, addr + len_data)]
            data = [d ^ self.scrambleCodeV2[i % 8] for i, d in enumerate(data)]
            res, rdata = self.cmd_verify_v2(bin_str_of_list(cmd_write + data))
            assert (res == 0x00)

    def verifyV2(self, mem):
        ## <aa> <len> <x> <addrL> <addrH> <x> <x> <x> <data[len+5]>
        cmd_verif = [0xa6, 0, 0, 0, 0, 0, 0, 0]

        print('len of hex:', len(mem))
        for addr in range(mem.minaddr(), mem.maxaddr() + 1, 56):
            print('Verifying 0x{:04X}: 0x{:02X} 0x{:02X}'.format(
                addr, mem[addr], mem[addr + 1]))
            # can only verify multiple of 8
            # if we are at the end and a smaller than 8 remains, verify
            # the last multiple of 8 bytes block
            len_data = (min(56, mem.maxaddr() + 1 - addr) + 7) // 8 * 8
            if addr + len_data > mem.maxaddr():
                add = mem.maxaddr() + 1 - len_data
            else:
                add = addr

            cmd_verif[3:5] = add & 0xFF, (add >> 8) & 0xFF
            data = [mem[add + a] for a in range(len_data)]
            data = [d ^ self.scrambleCodeV2[i % 8] for i, d in enumerate(data)]
            # len is data + 5, actual packet is data + 5 + 3
            cmd_verif[1] = 5 + len(data)
            res, rdata = self.cmd_verify_v2(bin_str_of_list(cmd_verif + data))
            assert (res == 0x00)

    def dumpV2(self, all):
        start_address = 0x3ff2 if all else 0x37f8
        cmd_verif = [0xa6, 0, 0, 0, 0, 0, 0, 0]
        cmd_verif[1] = 5 + 8
        # find block of 8 0xFF at the end of the device memory
        block = [0xff] * 8
        found = False
        data = [d ^ self.scrambleCodeV2[i % 8] for i, d in enumerate(block)]
        for address in range(start_address, -1, -1):
            print('Looking for 0xFF block at address 0x{:04X}'.format(
                address), end='\n')
            cmd_verif[3:5] = address & 0xFF, (address >> 8) & 0xFF
            r, _ = self.cmd_verify_v2(bin_str_of_list(cmd_verif + data))
            if r == 0:
                print('\nFound 0xFF block at address 0x{:04X}'.format(address))
                found = True
                break
        if not found:
            print('\nUnable to find 0xFF block')
            return
        memdump = IntelHex()
        memdump.puts(address, bin_str_of_list(block))

        print('Starting flash dumping')
        for i in reversed(block):
            print('{:02X} '.format(i), end='')
        sys.stdout.flush()

        nTry = 0
        nBytes = 0
        for address in range(address - 1, -1, -1):
            block[1:] = block[:-1]  # shift
            cmd_verif[3:5] = address & 0xFF, (address >> 8) & 0xFF
            found = False
            for i in range(256):
                val = stats[i]
                block[0] = val
                nTry += 1
                data = [d ^ self.scrambleCodeV2[i % 8]
                        for i, d in enumerate(block)]
                r, _ = self.cmd_verify_v2(bin_str_of_list(cmd_verif + data))
                if r == 0:  # verification ok, we found the correct byte
                    print('{:02X} '.format(val), end='')
                    sys.stdout.flush()
                    found = True
                    nBytes += 1
                    memdump[address] = val
                    break
            if not found:
                raise ValueError('Unable to find correct '
                                 'byte for address 0x{:04X}'.format(address))

        output_bin = 'out.bin'
        output_hex = 'out.hex'
        print('\nDone, writing output files {} and {}'.format(output_bin,
                                                              output_hex))
        print('Ntry = {} {:.2f}try/bytes'.format(nTry, float(nTry) / nBytes))
        memdump.tobinfile(output_bin)
        memdump.tofile(output_hex, format='hex')

    def start(self):
        cmd_start = [0xa2, 0, 0, 0x01]
        print('Sending reset command to start the program...')
        self.writeb(bin_str_of_list(cmd_start))
        # Chip will reset so no answer

    def readb(self, size):
        return self.epin.read(size)

    def writeb(self, b):
        self.epout.write(b)

    def dump(self):
        end_address = 0x3ff0
        # send the key
        b = '\xa6\x04' + struct.pack('BBBB', *scrambleCode)
        self.xcmd(b, 0)
        # find block of 16 0xFF at the end of the device memory
        block = [0xff] * 16
        found = False
        for address in range(end_address, -1, -1):
            print('\rLooking for address 0x{:04X}'.format(address), end='')
            r = self.cmd('\xa7\16' + struct.pack('<H', address) +
                         bin_str_of_list(scramble(block)))
            if r == 0:
                print('\nFound 0xFF block at address 0x{:04X}'.format(address))
                found = True
                break
        if not found:
            print('\nUnable to find 0xFF block')
            return

        memdump = IntelHex()
        memdump.puts(address, bin_str_of_list(block))

        print('Starting flash dumping')
        base = [0xa7, 16, 0, 0]
        nTry = 0
        nBytes = 0
        for address in range(address - 1, - 1, -1):
            block[1:] = block[:-1]  # shift
            base[2:4] = address & 0xFF, address >> 8
            found = False
            for i in range(256):
                i = stats[i]
                block[0] = i
                nTry += 1
                r = self.cmd(bin_str_of_list(base + scramble(block)), 4)
                if r == 0:  # verification ok, we found the correct byte
                    print('{:02X} '.format(i), end='')
                    sys.stdout.flush()
                    found = True
                    nBytes += 1
                    memdump[address] = i
                    break
            if not found:
                raise ValueError('Unable to find correct '
                                 'byte for address 0x{:04X}'.format(address))

        output_bin = 'out.bin'
        output_hex = 'out.hex'
        print('\nDone, writing output files {} and {}'.format(output_bin,
                                                              output_hex))
        print('Ntry = {} {:.2f}try/bytes'.format(nTry, float(nTry) / nBytes))
        memdump.tobinfile(output_bin)
        memdump.tofile(output_hex, format='hex')

args = parser.parse_args()

isp = WCHISP(debug=args.verbose)

# check chip ID and bootloader presence
info = isp.info()
if info not in range(0x51, 0x59 + 1):
    print("not a CH55x device")
    sys.exit(-1)
print('Found CH55{} device'.format(info - 0x50))
isp.set_key_v2()
print('Key set successfully')

if args.flash is not None:
    image = IntelHex()
    image.fromfile(args.flash, format='hex')
    isp.flashV2(image)
    isp.verifyV2(image)
    if args.start:
        isp.start()

elif args.dump:
    isp.dumpV2(args.all)

# dump flash
# isp.dump()
