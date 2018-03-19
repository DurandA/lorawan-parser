import unittest
from lorawan.message import MACMessage, JoinRequest, JoinAccept, UnconfirmedDataUp, UnconfirmedDataDown


class TestParse(unittest.TestCase):
    def test_parse_message(self):
        message = MACMessage.from_phy(bytes.fromhex("40F17DBE4900020001954378762B11FF0D"))

        assert bytes(message) == bytes.fromhex('40f17dbe4900020001954378762b11ff0d')
        assert message.mhdr == 0x40
        assert message.mac_payload == bytes.fromhex('f17dbe490002000195437876')
        assert message.mic == bytes.fromhex('2b11ff0d')
        assert message.f_opts == bytes()
        assert message.f_ctrl == b'\x00'
        # TODO check f_hdr
        assert message.dev_addr == 0x49be7df1
        assert message.f_cnt == 2
        assert message.f_port == 1
        assert message.frm_payload == bytes.fromhex('95437876')

        assert type(message) is UnconfirmedDataUp

        assert message.f_ctrl.ack == False
        assert message.f_ctrl.adr == False

    def test_parse_empty_payload_message(self):
        message = MACMessage.from_phy(bytes.fromhex("40F17DBE49000300012A3518AF"))

    def test_parse_large_message(self):
        pass

    def test_parse_ack(self):
        message = MACMessage.from_phy(bytes.fromhex("60f17dbe4920020001f9d65d27"))

        assert bytes(message) == bytes.fromhex('60f17dbe4920020001f9d65d27')
        assert message.mhdr == 0x60
        assert message.mac_payload == bytes.fromhex('f17dbe4920020001')
        assert message.mic == bytes.fromhex('f9d65d27')
        assert message.f_opts == bytes()
        assert message.f_ctrl == b'\x20'
        # TODO check f_hdr
        assert message.dev_addr == 0x49be7df1
        assert message.f_cnt == 2
        assert message.f_port == 1
        assert message.frm_payload == bytes()

        assert type(message) is UnconfirmedDataDown

        assert message.f_ctrl.ack == True
        assert message.f_ctrl.adr == False

    def test_parse_bogus_message(self):
        pass

    def test_parse_join_request(self):
        message = MACMessage.from_phy(bytes.fromhex("00dc0000d07ed5b3701e6fedf57ceeaf00c886030af2c9"))

        assert bytes(message) == bytes.fromhex('00dc0000d07ed5b3701e6fedf57ceeaf00c886030af2c9')
        assert message.mhdr == 0x00
        assert message.app_eui == 0x70B3D57ED00000DC
        assert message.dev_eui == 0x00AFEE7CF5ED6F1E
        assert message.dev_nonce == (0x86C8).to_bytes(2, byteorder='little')
        assert message.mic == bytes.fromhex('030AF2C9')

        assert type(message) is JoinRequest

    def test_parse_join_accept(self):
        message = MACMessage.from_phy(bytes.fromhex("20813f47f508ffa2670b6e23e01f84b9e25d9c4115f02eea0b3dd3e20b3eca92da"))

        assert bytes(message) == bytes.fromhex("20813f47f508ffa2670b6e23e01f84b9e25d9c4115f02eea0b3dd3e20b3eca92da")
        assert type(message) is JoinAccept

class TestMIC(unittest.TestCase):
    def test_calculate_and_verify_correct_mic_join_request(self):
        message = MACMessage.from_phy(bytes.fromhex("00dc0000d07ed5b3701e6fedf57ceeaf00c886030af2c9"))

        app_key = bytes.fromhex("00000000000000000000000000000000")
        calculated_mic = message.calculate_mic(app_key)
        
        #assert calculated_mic == bytes.fromhex('030af2C9')
        #assert message.verify_mic(app_key)

    def test_calculate_and_verify_correct_mic(self):
        message = MACMessage.from_phy(bytes.fromhex("40F17DBE49000300012A3518AF"))

        nwk_skey = bytes.fromhex("44024241ed4ce9a68c6a8bc055233fd3")
        calculated_mic = message.calculate_mic(nwk_skey)
        assert calculated_mic == bytes.fromhex('2a3518af')

        assert message.verify_mic(nwk_skey)


if __name__ == '__main__':
    unittest.main()
