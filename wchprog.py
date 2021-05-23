#!/usr/bin/python

import struct
import sys
import usb.core
import usb.util
import argparse

'''
Protocol:
Messages usually have a header of size 5 defined as follow:
CC xx LL 00 RR
msg[0] = CC: command
msg[1] = xx: dummy
msg[2] = LL: length of payload (length of message - 4)
msg[3] = 00
msg[4] = RR: response byte
'''

RESULT_IDX = 4
WCH52_CHIP_ID = 0x52

class Sim:
    def __init__(self):
        self.SnSum = 0
        self.CHIP_ID = WCH52_CHIP_ID

    def sim_data(self, to_device, from_device):
        if to_device[0] == 0xA7:
            # read config data
            self.SnSum = 0
            for i in range(4):
                self.SnSum += from_device[22 + i]
            self.SnSum = self.SnSum & 0xFF
            print(f"SIM: updated snSum:{hex(self.SnSum)}")
        elif to_device[0] == 0xA3:
            # calc new key
            Bootkey = [0] * 8
            if to_device[1] < 30:
                print(f"SIM: invalid length received {hex(to_device[1])}")
            else:
                i = int(to_device[1] / 7)
                Bootkey[0] = to_device[3 + i * 4] ^ self.SnSum
                Bootkey[2] = to_device[3 + i * 1] ^ self.SnSum
                Bootkey[3] = to_device[3 + i * 6] ^ self.SnSum
                Bootkey[4] = to_device[3 + i * 3] ^ self.SnSum
                Bootkey[6] = to_device[3 + i * 5] ^ self.SnSum
                i = int(to_device[1] / 5)
                Bootkey[1] = to_device[3 + i * 1] ^ self.SnSum
                Bootkey[5] = to_device[3 + i * 3] ^ self.SnSum
                Bootkey[7] = (self.CHIP_ID + Bootkey[0]) & 0xFF
                result = 0
                for i in range(8):
                    result = (result + Bootkey[i]) & 0xFF
                print(f"SIM: updated Bootkey: {list(map(hex, Bootkey))}, result returned = {hex(result)}")



class WCHISP:
    def __init__(self, version=1, verbose=True):
        self.verbose = verbose
        self.version = version
        self.simulator = Sim()
        # find our device
        dev = usb.core.find(idVendor=0x4348, idProduct=0x55e0)
        if dev is None:
            raise ValueError('Device not found')
        dev.reset()
        dev.set_configuration()
        cfg = dev.get_active_configuration()
        interface = cfg[(0, 0)]

        self.endpointOut = usb.util.find_descriptor(interface, custom_match=lambda e: usb.util.endpoint_direction(
            e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
        self.endpointIn = usb.util.find_descriptor(interface, custom_match=lambda e: usb.util.endpoint_direction(
            e.bEndpointAddress) == usb.util.ENDPOINT_IN)

    def assert_equal(self, a, b, msg=""):
        if a != b:
            raise Exception(
                f"Error, {hex(a) if type(a) == int else a} is not equal to {hex(b) if type(b) == int else b}, {msg}")

    def debug_print(self, message, data):
        if not self.verbose:
            return
        if type(data) == bytes:
            print("{} {}".format(message, repr(data)))
        else:
            print("{} {}".format(message, ' '.join([f'{v:02X}' for v in data])))

    def readBytes(self, size):
        data = self.endpointIn.read(size)
        self.debug_print("Reading {} bytes:".format(len(data)), data)
        return data

    def writeBytes(self, bytes):
        self.debug_print("Writing bytes:", bytes)
        self.endpointOut.write(bytes)

    def cmd(self, msg):
        self.writeBytes(msg)
        received = self.readBytes(64)
        if self.verbose:
            self.simulator.sim_data(msg, received)
        return received

    def expectedCommand(self, msg, exp):
        ret = self.cmd(msg)
        if ret != exp:
            xmsg = [hex(x) for x in msg[0:4]]
            raise Exception('cmd[{}] return {} != {}'.format(','.join(xmsg), list(map(hex, ret)), hex(exp)))

    def command_with_expected_result(self, data, expected_results):
        ret = self.cmd(data)
        for (index, value, message) in expected_results:
            if ret[index] != value:
                raise Exception(f"Error, ret[{index}]={hex(ret[index])} is not exepected {hex(value)}, {message}")
        return ret


    def info(self):
        if self.version == 1:
            v = self.cmd(b'\xa2\x13USB DBG CH559 & ISP' + b'\0' * 42)
            self.cmd(b'\xbb\x00')
        else:
            v = self.cmd(b'\xa1\x12\x00R\x11MCU ISP & WCH.CN')
            if len(v) == 6:
                chip_id = v[4]
                return chip_id

        return v

    def flash_or_verify_v2(self, memory, bootkey, verify=True):
        code = 0xA6 if verify else 0xA5
        message = "verifying" if verify else "writing"
        print(f"{message}:", end="")
        addr = 0
        while addr < len(memory):
            size = min(len(memory) - addr, 0x38)
            if verify and size < 0x38:
                diff = 0x38 - size
                addr -= diff
                size += diff
            extra_header_size = 5
            data = [code, extra_header_size + size, 0]
            data += [addr & 0xFF, (addr >> 8) & 0xFF]
            data += [0x00, 0x00, 0x00]
            for i in range(size):
                data.append(memory[addr + i])
                if (i % 8) == 7:
                    data[-1] ^= bootkey
            ret = self.cmd(data)
            self.command_with_expected_result(
                data, [(RESULT_IDX, 0x00, f"Error {message} data at: {hex(addr)} of size {size}")])
            addr += size
            sys.stdout.write('#')
            sys.stdout.flush()
        print('')

    def read_config_generate_key(self):
        data = self.command_with_expected_result(
            [0xA7, 0x02, 0x00, 0x1F, 0x00],
            [(0, 0xA7, "invalid reading config reply header"),
             ])
        # verify correct data received
        self.assert_equal(data[2] + 4, len(data), "invalid config reply length")

        inputKey = data[22:26]
        snSum = sum(inputKey) & 0xFF
        lastKey = snSum ^ 0x00 + WCH52_CHIP_ID
        if self.verbose:
            print(f"***** Input Key is {list(map(hex, inputKey))}")
            print(f"***** SNSum is {hex(snSum)}")
            print(f"***** lastKey is {hex(lastKey)}")
        payload_size = 30
        header_size = 3
        xorData = snSum ^ 0x00
        outData = [0xA3, payload_size + header_size, 0x00] + [xorData] * payload_size
        bootKey = ((snSum ^ xorData) * 8 + WCH52_CHIP_ID) & 0xFF
        self.command_with_expected_result(outData, [(0, 0xA3, "invalid setting key reply header"),
                                                    (RESULT_IDX, bootKey, "invalid bootkey received")])
        return bootKey

    def program(self, hexfile):
        def readhex():
            lno = 0
            mem = []
            with open(hexfile, 'r') as f:
                for line in f:
                    lno += 1
                    line = line.strip()
                    if len(line) < 6 or line[0] != ':': continue
                    if line[7:9] == '01': break
                    if line[7:9] != '00':
                        raise ValueError('Error reading input hexfile: unknown data type @ %s:%d' % (hexfile, lno))
                    n = int(line[1:3], 16)
                    addr = int(line[3:7], 16)
                    if n + addr > len(mem):
                        mem.extend([255] * (n + addr - len(mem)))
                    i = 9
                    while n > 0:
                        mem[addr] = int(line[i:i + 2], 16)
                        i += 2
                        addr += 1
                        n -= 1
            return mem

        def wv(mode):
            if mode == '\xa7':
                print('Verifying ', end=' ')
            else:
                print('Programming ', end=' ')
            sys.stdout.flush()

            addr = 0
            while addr < len(mem):
                b = mode
                sz = len(mem) - addr
                if sz > 0x3c: sz = 0x3c
                b += struct.pack('<BH', sz, addr)
                for i in range(sz):
                    b += chr(mem[addr + i] ^ rand[i % 4])
                self.expectedCommand(b, 0)
                addr += sz
                sys.stdout.write('#')
                sys.stdout.flush()
            print('')

        mem = readhex()
        if len(mem) < 256 or len(mem) > 16384:
            raise "hexfile codesize %d not in (256, 16384)" % len(mem)

        if self.version == 1:
            rand = (0x29, 0x52, 0x8C, 0x70)

            b = b'\xa6\x04' + struct.pack('BBBB', *rand)
            self.expectedCommand(b, 0)
            for page in range(0, 0x40, 4):
                b = b'\xa9\x02\x00' + chr(page)
                self.expectedCommand(b, 0)

            wv(b'\xa8')

            self.cmd(b'\xb8\x02\xff\x4e')  # Code_Protect, Boot_Load, No_Long_Reset, No_RST
            self.cmd(b'\xb9\x00')

            wv(b'\xa7')
            self.writeBytes(b'\xa5\x02\x00\x00')
        elif self.version == 2:
            # read config
            print("Reading config and generating key")
            bootKey = self.read_config_generate_key()

            # erase flash
            print("Erasing flash")
            number_of_pages = 8
            self.command_with_expected_result(
                [0xA4, 0x01, 0x00, number_of_pages],
                [(RESULT_IDX, 0x00, "invalid erase returned code")])
            # flash
            self.flash_or_verify_v2(mem, bootKey, verify=False)
            # verify
            self.flash_or_verify_v2(mem, bootKey, verify=True)
            # run program, exit bootloader
            print('All done, starting program...')
            self.writeBytes([0xA2, 0x01, 0x00, 0x01])

parser = argparse.ArgumentParser()
parser.add_argument("hexfile", help="The Intel-hex file to program")
parser.add_argument("-v", "--verbose", help="Enable debug verbosity",
                    action="store_true")
parser.add_argument("-b", "--bootloader", help="Specify bootloader version", type=int, default=1)
args = parser.parse_args()
print(f"args are: verbose:{args.verbose} hex:{args.hexfile} bootloader:{args.bootloader}")
isp = WCHISP(version=args.bootloader, verbose=args.verbose)
info = isp.info()
if info == WCH52_CHIP_ID:
    print(f"Found chip id {hex(info)}, CH552 detected!")
    isp.program(args.hexfile)
else:
    print(f"Error, invalid device id received: {hex(info)}")
