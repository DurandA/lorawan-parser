import struct, array
from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms


hexlify = lambda x: "".join("{:02X}".format(c) for c in x)

class FrameControl(object):
    def __init__(self, ctrl_byte):
        self.ctrl_byte = ctrl_byte

    @property
    def adr(self):
        return bool(self.ctrl_byte & 0x80)
    @property
    def bit6(self):
        return bool(self.ctrl_byte & 0x40)
    @property
    def ack(self):
        return bool(self.ctrl_byte & 0x20)
    @property
    def bit4(self):
        return bool(self.ctrl_byte & 0x10)
    @property
    def f_opts_len(self):
        return self.ctrl_byte & 0x0f

    def __bytes__(self):
        return bytes([self.ctrl_byte])

    def __eq__(self, other):
        return bytes(self) == other

    def __ne__(self, other):
        return not self.__eq__(other)

class DownlinkFrameControl(FrameControl):
    rfu = FrameControl.bit6
    f_pending = FrameControl.bit4

class UplinkFrameControl(FrameControl):
    adr_ack_req = FrameControl.bit6
    rfu = FrameControl.bit4

class FrameHeader(object):
    def __init__(self, mac_payload, direction):
        self.dev_addr = mac_payload[:4] # little-endian
        f_ctrl = mac_payload[4]
        if direction:
            self.f_ctrl = DownlinkFrameControl(f_ctrl)
        else:
            self.f_ctrl = UplinkFrameControl(f_ctrl)
        self.f_cnt = int.from_bytes(mac_payload[5:7], byteorder='little') # little-endian
        self.f_opts = mac_payload[7:7+self.f_opts_len]

    # @property
    # def adr(self):
    #     return self.f_ctrl.adr
    # @property
    # def rfu(self):
    #     return self.f_ctrl.rfu
    # @property
    # def ack(self):
    #     return self.f_ctrl.ack
    # @property
    # def f_pending(self):
    #     return self.f_ctrl.f_pending
    @property
    def f_opts_len(self):
        return self.f_ctrl.f_opts_len
    # @property
    # def adr_ack_req(self):
    #     return self.f_ctrl.adr_ack_req

    def __bytes__(self):
        return ( bytes(self.dev_addr)
                + bytes(self.f_ctrl)
                + self.f_cnt.to_bytes(2, 'little')
                + self.f_opts )

    def __len__(self):
        return 7+self.f_opts_len

class MACMessage(object):
    @property
    def is_data_message(self):
        # TODO: set mtype
        if self.mtype in (
                UnconfirmedDataUp,
                UnconfirmedDataDown,
                ConfirmedDataUp,
                ConfirmedDataDown):
            return True
        return False

    def __bytes__(self):
        return bytes([self.mhdr]) + self.mac_payload + self.mic

    # TODO remove
    @property
    def mtype(self):
        return message_types[self.mhdr >> 5]

    @classmethod
    def from_phy(cls, phy_payload):
        return cls.factory(
            mhdr=phy_payload[0], #payload[:1]
            payload=phy_payload[1:-4],
            mic=phy_payload[-4:]
        )

    @classmethod
    def factory(cls, mhdr, payload, mic):
        mtype, _, _ = (mhdr >> 5, mhdr & 0x03, mhdr & 0x1c)
        return message_types[mtype](mhdr, payload, mic)

    def __init__(self, mhdr, payload, mic):
        self.mhdr = mhdr
        mtype, _, _ = (mhdr >> 5, mhdr & 0x03, mhdr & 0x1c)
        self.mac_payload = payload
        self.mic = mic

    def calculate_mic(self):
        raise NotImplementedError('MIC is not yet implemented for %s' % type(self).__name__)

    def verify_mic(self, nwk_skey):
        return self.calculate_mic(nwk_skey) == self.mic

    def __str__(self):
        return '%s' % type(self).__name__

class JoinRequest(MACMessage):
    def __init__(self, mhdr, join_request, mic):
        super().__init__(mhdr, join_request, mic)
        assert self.mtype is JoinRequest
        self.app_eui = int.from_bytes(join_request[:8], byteorder='little') # little-endian
        self.dev_eui = int.from_bytes(join_request[8:16], byteorder='little') # little-endian
        self.dev_nonce = join_request[16:] # little-endian

    def calculate_mic(self, app_key):
        msg = ( bytes([self.mhdr])
                + self.app_eui.to_bytes(8, byteorder='little')
                + self.dev_eui.to_bytes(8, byteorder='little')
                + bytes(self.dev_nonce) )
        c = CMAC(algorithms.AES(app_key), backend=default_backend())
        c.update(msg)
        cmac = c.finalize()
        mic = cmac[0:4]
        return mic

    @property
    def join_request(self):
        return self.mac_payload

    def __str__(self):
        return '{} ({:x}, {:x})'.format(super().__str__(), self.app_eui, self.dev_eui)

class JoinAccept(MACMessage):
    def __init__(self, mhdr, join_response, mic):
        super().__init__(mhdr, join_response, mic)
        assert self.mtype is JoinAccept
        self.app_nonce = join_response[:3] # 3 bytes little-endian
        self.net_id = join_response[3:6] # 3 bytes little-endian
        self.dev_addr = int.from_bytes(join_response[6:10], byteorder='little') # 4 bytes little-endian
        self.dl_settings = join_response[10] # 1 byte
        self.rx_delay = join_response[11] # 1 byte
        if len(join_response) == 12+16:
            self.cf_list = join_response[12:] # 16 bytes, optional
        else:
            self.cf_list = bytes()

    def calculate_mic(self, app_key):
        msg = ( bytes([self.mhdr])
                + bytes(self.app_nonce)
                + bytes(self.net_id)
                + self.dev_addr.to_bytes(4, byteorder='little')
                + bytes([self.dl_settings])
                + bytes([self.rx_delay])
                + bytes(self.cf_list) )
        c = CMAC(algorithms.AES(app_key), backend=default_backend())
        c.update(msg)
        cmac = c.finalize()
        mic = cmac[0:4]
        return mic

    @property
    def join_response(self):
        return self.mac_payload

class DataMessage(MACMessage):
    def __init__(self, mhdr, mac_payload, mic):
        super().__init__(mhdr, mac_payload, mic)
        assert self.is_data_message
        #self.__cls__ = self.mtype
        self.f_hdr = FrameHeader(mac_payload, self.direction)

        if len(self.f_hdr) != len(mac_payload):
            self.f_port = int.from_bytes(mac_payload[len(self.f_hdr):len(self.f_hdr)+1], byteorder='little')
            self.frm_payload = mac_payload[len(self.f_hdr)+1:]
        else:
            self.f_port = bytes()
            self.frm_payload = bytes()

    def calculate_mic(self, nwk_skey):
        msg = ( bytes([self.mhdr])
                + bytes(self.f_hdr)
                + bytes([self.f_port])
                + bytes(self.frm_payload) )
        b0 = ( b'\x49\x00\x00\x00\x00'
                + bytes([self.direction])
                + self.dev_addr.to_bytes(4, 'little')
                + self.f_cnt.to_bytes(4, 'little')
                + b'\x00'+bytes([len(msg)]) )
        c = CMAC(algorithms.AES(nwk_skey), backend=default_backend())
        c.update(b0 + msg)
        cmac = c.finalize()
        mic = cmac[0:4]
        return mic

    def __str__(self):
        return '{} ({:08x})'.format(super().__str__(), self.dev_addr)

    @property
    def dev_addr(self):
        return int.from_bytes(self.f_hdr.dev_addr, byteorder='little')

    @property
    def f_ctrl(self):
        return self.f_hdr.f_ctrl
    @property
    def f_cnt(self):
        return self.f_hdr.f_cnt
    @property
    def f_opts(self):
        return self.f_hdr.f_opts

class UnconfirmedDataUp(DataMessage):
    direction = 0
class UnconfirmedDataDown(DataMessage):
    direction = 1
class ConfirmedDataUp(DataMessage):
    direction = 0
class ConfirmedDataDown(DataMessage):
    direction = 1

message_types = {
    0: JoinRequest,
    1: JoinAccept,
    2: UnconfirmedDataUp,
    3: UnconfirmedDataDown,
    4: ConfirmedDataUp,
    5: ConfirmedDataDown
}
