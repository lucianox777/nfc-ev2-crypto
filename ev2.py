"""
This code was implemented based on AN12196.
"""

import io
import os
import struct
from enum import Enum
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util.strxor import strxor


def byte_rot_left(x):
    return x[1:] + x[0:1]


def byte_rot_right(x):
    return x[-1:] + x[:-1]


def require(msg, condition):
    if not condition:
        raise RuntimeError("Condition failed: {}".format(msg))


class AuthenticateEV2:
    """
    Perform AuthenticateEV2First handshake with the specified authorization key.
    """

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
        require("R-APDU length", len(part1_resp) == 18)
        require("status code 91AF", part1_resp[-2:] == b"\x91\xAF")
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
        require("R-APDU length", len(part2_resp) == 34)
        require("status code 9100", part2_resp[-2:] == b"\x91\x00")
        enc = part2_resp[:32]

        cipher = AES.new(self.auth_key, AES.MODE_CBC, IV=b"\x00" * 16)
        resp = cipher.decrypt(enc)
        resp_s = io.BytesIO(resp)
        ti = resp_s.read(4)
        rnda_p = resp_s.read(16)
        pdcap2 = resp_s.read(6)
        pcdcap2 = resp_s.read(6)
        recv_rnda = byte_rot_right(rnda_p)
        require("generated RndA == decrypted RndA", recv_rnda == self.rnda)

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


class CommMode(Enum):
    PLAIN = 1
    MAC = 2
    FULL = 3


class CryptoComm:
    """
    This class represents an authenticated session after AuthentivateEV2 command.
    It offers the ability to prepare APDUs for CommMode.MAC or CommMode.FULL and validate R-APDUs in these modes.
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

    def wrap_cmd(self, ins: int, mode: CommMode, header: bytes = None, data: bytes = None) -> bytes:
        """
        Wrap commend into APDU with CommMode.PLAIN/MAC/FULL
        :param ins: command code, e.g. 0x8D (ISO SELECT CC)
        :param header: command header, e.g. b"\x03\x00\x00\x00\x0A\x00\x00"
        :param data: command data, e.g. b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A"
        :param mode: communication mode
        :return: wrapped APDU (bytes)
        """
        if header is None:
            header = b""

        if data is None:
            data = b""

        payload_len = len(header) + len(data)
        apdu = b"\x90" + bytes([ins]) + b"\x00\x00" + bytes([payload_len]) + header + data + b"\x00"

        if mode == CommMode.PLAIN:
            self.cmd_counter += 1
            return apdu
        elif mode == CommMode.MAC:
            return self.sign_apdu(apdu)
        elif mode == CommMode.FULL:
            return self.encrypt_apdu(apdu, len(header))

        raise RuntimeError("Invalid CommMode specified.")

    def sign_apdu(self, apdu: bytes) -> bytes:
        """
        Convert CommMode.PLAIN APDU into CommMode.MAC
        :param apdu: Plain APDU
        :return: Signed APDU
        """
        if self.ti is None:
            raise RuntimeError("TI was not set.")

        # [CLS=90] [INS] [P1=00] [P2=00] [Lc] [data...] [Le=0]
        require("APDU CLS=0x90", apdu[0] == 0x90)
        require("APDU P1=0x00", apdu[2] == 0x00)
        require("APDU P2=0x00", apdu[3] == 0x00)
        require("APDU Lc valid", apdu[4] == len(apdu) - 6)
        require("APDU Le=0x00", apdu[-1] == 0x00)

        cmd = apdu[1:2]
        cmd_cntr_b = struct.pack("<H", self.cmd_counter)
        ti = self.ti
        data = apdu[5:-1]
        mact = self.calc_raw_data(cmd + cmd_cntr_b + ti + data)
        new_len = bytes([apdu[4] + len(mact)])
        require("APDU Data shorter than 256 bytes", len(new_len) == 1)

        self.cmd_counter += 1
        return b"\x90" + cmd + b"\x00\x00" + new_len + data + mact + b"\x00"

    def encrypt_apdu(self, apdu, data_offset):
        """
        Convert CommMode.PLAIN APDU into CommMode.FULL
        :param apdu: Plain APDU
        :param data_offset: length of the command header (how many data bytes should get through unencrypted)
        :return: Encrypted APDU
        """
        require("APDU CLS=0x90", apdu[0] == 0x90)
        require("APDU P1=0x00", apdu[2] == 0x00)
        require("APDU P2=0x00", apdu[3] == 0x00)
        require("APDU Lc valid", apdu[4] == len(apdu) - 6)
        require("APDU Le=0x00", apdu[-1] == 0x00)

        header = apdu[5:5 + data_offset]

        iv_b = b"\xA5\x5A" + self.ti + struct.pack("<H", self.cmd_counter) + 8 * b"\x00"
        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_ECB)
        iv = cipher.encrypt(iv_b)

        plainstream = io.BytesIO()
        plainstream.write(apdu[5+data_offset:-1])
        plainstream.write(b"\x80")

        while plainstream.getbuffer().nbytes % AES.block_size != 0:
            plainstream.write(b"\x00")

        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_CBC, IV=iv)
        enc = cipher.encrypt(plainstream.getvalue())
        new_len = bytes([len(header) + len(enc)])
        require("APDU Data shorter than 256 bytes", len(new_len) == 1)

        return self.sign_apdu(b"\x90" + apdu[1:2] + b"\x00\x00" + new_len + header + enc + b"\x00")

    def parse_response(self, res: bytes) -> Tuple[bytes, bytes]:
        """
        Parse and check signature for R-APDU
        :param res: R-APDU
        :return: tuple(status code, response data)
        """
        require("Response code 91xx", res[-2] == 0x91)
        status = res[-2:]
        mact = res[-10:-2]
        data = res[:-10]

        our_mact = self.calc_raw_data(status[1:2] + struct.pack("<H", self.cmd_counter) + self.ti + data)

        require("Received MAC == calculated MAC", mact == our_mact)
        return status, data

    def decrypt_response(self, data: bytes) -> bytes:
        """
        Decrypt CommMode.FULL response data
        :param data: encrypted response data returned from validate_response()
        :return: decrypted data with optional padding (trailing 80 00 00 00 ...)
        """
        iv_b = b"\x5A\xA5" + self.ti + struct.pack("<H", self.cmd_counter) + 8 * b"\x00"
        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_ECB)
        iv = cipher.encrypt(iv_b)

        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_CBC, IV=iv)
        return cipher.decrypt(data)

    def unwrap_res(self, res: bytes, mode: CommMode) -> Tuple[bytes, bytes]:
        """
        Process response in any communication mode
        :param res: R-APDU (bytes)
        :param mode: CommMode
        :return: tuple(status, response data)
        """
        if mode == CommMode.PLAIN:
            require("Response code 91xx", res[-2] == 0x91)
            status_code = res[-2:]
            data = res[:-2]
            return status_code, data
        elif mode == CommMode.MAC:
            status_code, data = self.parse_response(res)
            return status_code, data
        elif mode == CommMode.FULL:
            status_code, enc_data = self.parse_response(res)
            return status_code, self.decrypt_response(enc_data)
