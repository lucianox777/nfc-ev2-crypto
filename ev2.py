"""
This code was implemented based on AN12196.
"""

import binascii
import io
import os
import struct
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util.strxor import strxor


def byte_rot_left(x):
    return x[1:] + x[0:1]


def byte_rot_right(x):
    return x[-1:] + x[:-1]


class AuthenticateEV2:
    def __init__(self, auth_key):
        self.auth_key = auth_key

        self.rnda = None
        self.rndb = None

    def init(self, key_no: bytes) -> bytes:
        """
        Generate the initial APDU to begin authentication process.
        :param key_no: key number (one byte)
        :return: initial C-APDU
        """
        # [KeyNo] [LenCap]
        params = key_no + b"\x00"
        return b"\x90\x71\x00\x00\x02" + params + b"\x00"

    def generate_rnda(self):
        return os.urandom(16)

    def part1(self, part1_resp: bytes) -> bytes:
        """
        Take the first R-APDU and generate the response.
        :param part1_resp: first R-APDU (response to init())
        :return: response C-APDU
        """
        assert len(part1_resp) == 18
        assert part1_resp[-2:] == b"\x91\xAF"
        rndb_enc = part1_resp[:16]

        cipher = AES.new(self.auth_key, AES.MODE_CBC, IV=b"\x00" * 16)
        self.rndb = cipher.decrypt(rndb_enc)
        self.rnda = self.generate_rnda()
        rndb_p = byte_rot_left(self.rndb)
        cipher = AES.new(self.auth_key, AES.MODE_CBC, IV=b"\x00" * 16)
        resp = cipher.encrypt(self.rnda + rndb_p)
        part2_cmd = b"\x90\xAF\x00\x00\x20" + resp + b"\x00"
        return part2_cmd

    def part2(self, part2_resp: bytes) -> 'CryptoComm':
        """
        Validate final R-APDU and create secure messaging object
        :param part2_resp: final R-APDU
        :return: CryptoComm object
        """
        assert len(part2_resp) == 34
        assert part2_resp[-2:] == b"\x91\x00"
        enc = part2_resp[:32]

        cipher = AES.new(self.auth_key, AES.MODE_CBC, IV=b"\x00" * 16)
        resp = cipher.decrypt(enc)
        resp_s = io.BytesIO(resp)
        ti = resp_s.read(4)
        rnda_p = resp_s.read(16)
        pdcap2 = resp_s.read(6)
        pcdcap2 = resp_s.read(6)
        recv_rnda = byte_rot_right(rnda_p)
        assert recv_rnda == self.rnda

        stream = io.BytesIO()
        # they are counting from right to left :D
        stream.write(self.rnda[0:2])  # [RndA[15:14]
        stream.write(strxor(self.rnda[2:8], self.rndb[0:6]))  # [ (RndA[13:8] ⊕ RndB[15:10]) ]
        stream.write(self.rndb[-10:])  # [RndB[9:0]
        stream.write(self.rnda[-8:])  # RndA[7:0]
        # just took me an hour or two to brute force it from the examples

        sv1stream = io.BytesIO()
        sv1stream.write(b"\xA5\x5A\x00\x01\x00\x80")
        sv1stream.write(stream.getvalue())
        sv1 = sv1stream.getvalue()

        sv2stream = io.BytesIO()
        sv2stream.write(b"\x5A\xA5\x00\x01\x00\x80")
        sv2stream.write(stream.getvalue())
        sv2 = sv2stream.getvalue()

        c = CMAC.new(self.auth_key, ciphermod=AES)
        c.update(sv1)
        k_ses_auth_enc = c.digest()

        c = CMAC.new(self.auth_key, ciphermod=AES)
        c.update(sv2)
        k_ses_auth_mac = c.digest()

        return CryptoComm(k_ses_auth_mac, k_ses_auth_enc, ti=ti, pdcap2=pdcap2, pcdcap2=pcdcap2)


class CryptoComm:
    """
    Prepare APDUs for CommMode.MAC or CommMode.FULL, validate R-APDUs in these modes.
    """

    def __init__(self, k_ses_auth_mac: bytes,
                 k_ses_auth_enc: bytes = None,
                 *,
                 ti: bytes = None,
                 cmd_counter: int = 0,
                 pdcap2: bytes = None,
                 pcdcap2: bytes = None):
        self.k_ses_auth_mac = k_ses_auth_mac
        self.k_ses_auth_enc = k_ses_auth_enc
        self.ti = ti
        self.cmd_counter = cmd_counter
        self.pdcap2 = pdcap2
        self.pcdcap2 = pcdcap2

    def calc_raw_data(self, data: bytes) -> bytes:
        """
        Calculate CMAC for raw data.
        :param data: raw data
        :return: CMAC
        """
        c = CMAC.new(self.k_ses_auth_mac, ciphermod=AES)
        c.update(data)
        mac = c.digest()
        return bytes(bytearray([mac[i] for i in range(16) if i % 2 == 1]))

    def sign_apdu(self, apdu: bytes) -> bytes:
        """
        Convert CommMode.PLAIN APDU into CommMode.MAC
        :param apdu: Plain APDU
        :return: Signed APDU
        """
        if self.ti is None:
            raise RuntimeError("TI was not set.")

        # [CLS=90] [INS] [P1=00] [P2=00] [Lc] [data...] [Le=0]
        assert apdu[0] == 0x90
        assert apdu[2] == 0x00
        assert apdu[3] == 0x00
        assert apdu[4] == len(apdu) - 6
        assert apdu[-1] == 0x00

        cmd = apdu[1:2]
        cmd_cntr_b = struct.pack("<H", self.cmd_counter)
        ti = self.ti
        data = apdu[5:-1]
        mact = self.calc_raw_data(cmd + cmd_cntr_b + ti + data)
        new_len = bytes([apdu[4] + len(mact)])
        assert len(new_len) == 1

        self.cmd_counter += 1
        return b"\x90" + cmd + b"\x00\x00" + new_len + data + mact + b"\x00"

    def check_response(self, res: bytes) -> Tuple[bytes, bytes]:
        """
        Parse and check signature for R-APDU
        :param res: R-APDU
        :return: tuple(status code, response data)
        """
        assert res[0] == 0x91
        mact = self.calc_raw_data(res[1:2] + struct.pack("<H", self.cmd_counter) + self.ti + res[2:-8])
        assert mact == res[-8:]
        return res[0:2], res[2:-8]

    def encrypt_apdu(self, apdu, data_offset):
        assert apdu[0] == 0x90
        assert apdu[2] == 0x00
        assert apdu[3] == 0x00
        assert apdu[4] == len(apdu) - 6
        assert apdu[-1] == 0x00

        header = apdu[5:5 + data_offset]

        iv_b = b"\xA5\x5A" + self.ti + struct.pack("<H", self.cmd_counter) + 8 * b"\x00"
        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_ECB)
        iv = cipher.encrypt(iv_b)

        plainstream = io.BytesIO()
        plainstream.write(apdu[5+data_offset:-1])
        pad_byte = b"\x80"

        while plainstream.getbuffer().nbytes % AES.block_size != 0:
            plainstream.write(pad_byte)
            pad_byte = b"\x00"

        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_CBC, IV=iv)
        enc = cipher.encrypt(plainstream.getvalue())
        new_len = bytes([len(header) + len(enc)])
        assert len(new_len) == 1

        return self.sign_apdu(b"\x90" + apdu[1:2] + b"\x00\x00" + new_len + header + enc + b"\x00")


if __name__ == "__main__":
    # AN12196 Section 6.6 Page 28
    auth = AuthenticateEV2(b"\x00" * 16)
    auth.generate_rnda = lambda: b"\x13\xC5\xDB\x8A\x59\x30\x43\x9F\xC3\xDE\xF9\xA4\xC6\x75\x36\x0F"

    assert auth.init(b"\x00") == b"\x90\x71\x00\x00\x02\x00\x00\x00"

    resp = auth.part1(b"\xA0\x4C\x12\x42\x13\xC1\x86\xF2\x23\x99\xD3\x3A\xC2\xA3\x02\x15\x91\xAF")
    assert resp == binascii.unhexlify("90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00")

    comm = auth.part2(
        b"\x3F\xA6\x4D\xB5\x44\x6D\x1F\x34\xCD\x6E\xA3\x11\x16\x7F\x5E\x49"
        b"\x85\xB8\x96\x90\xC0\x4A\x05\xF1\x7F\xA7\xAB\x2F\x08\x12\x06\x63"
        b"\x91\x00")
    assert comm.ti == binascii.unhexlify("9d00c4df")
    assert comm.pdcap2 == binascii.unhexlify("000000000000")
    assert comm.pcdcap2 == binascii.unhexlify("000000000000")
    assert comm.k_ses_auth_enc == binascii.unhexlify("1309C877509E5A215007FF0ED19CA564")
    assert comm.k_ses_auth_mac == binascii.unhexlify("4C6626F5E72EA694202139295C7A7FC7")

    # AN12196 Section 6.10 Page 34
    auth = AuthenticateEV2(b"\x00" * 16)
    auth.generate_rnda = lambda: binascii.unhexlify("B98F4C50CF1C2E084FD150E33992B048")

    assert auth.init(b"\x00") == b"\x90\x71\x00\x00\x02\x00\x00\x00"

    resp = auth.part1(binascii.unhexlify("B875CEB0E66A6C5CD00898DC371F92D191AF"))
    assert resp == binascii.unhexlify("90AF000020FF0306E47DFBC50087C4D8A78E88E62DE1E8BE457AA477C707E2F0874916A8B100")

    comm = auth.part2(
        binascii.unhexlify("0CC9A8094A8EEA683ECAAC5C7BF20584206D0608D477110FC6B3D5D3F65C3A6A9100"))
    assert comm.ti == binascii.unhexlify("7614281A")
    assert comm.pdcap2 == binascii.unhexlify("000000000000")
    assert comm.pcdcap2 == binascii.unhexlify("000000000000")
    assert comm.k_ses_auth_enc == binascii.unhexlify("7A93D6571E4B180FCA6AC90C9A7488D4")
    assert comm.k_ses_auth_mac == binascii.unhexlify("FC4AF159B62E549B5812394CAB1918CC")

    # AN12196 Section 5.3 Page 21
    m = CryptoComm(k_ses_auth_mac=binascii.unhexlify("8248134A386E86EB7FAF54A52E536CB6"))
    mact = m.calc_raw_data(binascii.unhexlify("F500007A21085E02"))
    assert mact == binascii.unhexlify("6597A457C8CD442C")

    m = CryptoComm(k_ses_auth_mac=binascii.unhexlify("8248134A386E86EB7FAF54A52E536CB6"),
                   ti=b"\x7A\x21\x08\x5E",
                   cmd_counter=0)
    assert m.sign_apdu(b"\x90\xF5\x00\x00\x01\x02\x00") == binascii.unhexlify("90F5000009026597A457C8CD442C00")

    # seems like SW1=91 at the beginning was omitted in the example, added it by hand
    status_code, data = m.check_response(binascii.unhexlify("91000040EEEE000100D1FE001F00004400004400002000006A00002A474282E7A47986"))
    assert status_code.hex() == "9100"
    assert data.hex() == "0040eeee000100d1fe001f00004400004400002000006a0000"

    # AN12196 Section 5.4 Page 22
    m = CryptoComm(k_ses_auth_mac=binascii.unhexlify("4C6626F5E72EA694202139295C7A7FC7"),
                   k_ses_auth_enc=binascii.unhexlify("1309C877509E5A215007FF0ED19CA564"),
                   ti=binascii.unhexlify("9D00C4DF"),
                   cmd_counter=0)
    res = m.encrypt_apdu(binascii.unhexlify("908D000097020000008000000051D1014D550463686F6F73652E75726C2E636F6D2F6E7461673432343F653D303030303030303030303030303030303030303030303030303030303030303026633D303030303030303030303030303030300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000"), data_offset=7)
    proper = binascii.unhexlify("908D00009F02000000800000421C73A27D827658AF481FDFF20A5025B559D0E3AA21E58D347F343CFFC768BFE596C706BC00F2176781D4B0242642A0FF5A42C461AAF894D9A1284B8C76BCFA658ACD40555D362E08DB15CF421B51283F9064BCBE20E96CAE545B407C9D651A3315B27373772E5DA2367D2064AE054AF996C6F1F669170FA88CE8C4E3A4A7BBBEF0FD971FF532C3A802AF745660F2B4D1D9A8499661EBF300")
    assert res == proper

    status_code, data = m.check_response(binascii.unhexlify("9100FC222E5F7A542452"))
    assert status_code == b"\x91\x00"
    assert data == b""

    # AN12196 Section 6.12 Page 36
    m = CryptoComm(binascii.unhexlify("FC4AF159B62E549B5812394CAB1918CC"), ti=binascii.unhexlify("7614281A"), cmd_counter=0, k_ses_auth_enc=binascii.unhexlify("7A93D6571E4B180FCA6AC90C9A7488D4"))
    res = m.encrypt_apdu(binascii.unhexlify("908D000011030000000A00000102030405060708090A00"), data_offset=7)
    proper = binascii.unhexlify("908D00001F030000000A00006B5E6804909962FC4E3FF5522CF0F8436C0C53315B9C73AA00")
    assert res == proper

    status_code, data = m.check_response(binascii.unhexlify("9100C26D236E4A7C046D"))
    assert status_code == b"\x91\x00"
    assert data == b""
