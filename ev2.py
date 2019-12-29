import binascii
import io
import os

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util.strxor import strxor


def byte_rot_left(x):
    return x[1:] + x[0:1]


def byte_rot_right(x):
    return x[-1:] + x[:-1]


class AuthenticateEV2:
    def __init__(self):
        self.rnda = None
        self.rndb = None

    def init(self):
        # [KeyNo] [LenCap]
        params = b"\x00\x00"
        return b"\x90\x71\x00\x00\x02" + params + b"\x00"

    def generate_rnda(self):
        return os.urandom(16)

    def part1(self, part1_resp):
        assert len(part1_resp) == 18
        assert part1_resp[-2:] == b"\x91\xAF"
        rndb_enc = part1_resp[:16]

        cipher = AES.new(b"\x00" * 16, AES.MODE_CBC, IV=b"\x00" * 16)
        self.rndb = cipher.decrypt(rndb_enc)
        self.rnda = self.generate_rnda()
        rndb_p = byte_rot_left(self.rndb)
        cipher = AES.new(b"\x00" * 16, AES.MODE_CBC, IV=b"\x00" * 16)
        resp = cipher.encrypt(self.rnda + rndb_p)
        part2_cmd = b"\x90\xAF\x00\x00\x20" + resp + b"\x00"
        return part2_cmd

    def part2(self, part2_resp):
        assert len(part2_resp) == 34
        assert part2_resp[-2:] == b"\x91\x00"
        enc = part2_resp[:32]

        cipher = AES.new(b"\x00" * 16, AES.MODE_CBC, IV=b"\x00" * 16)
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
        # but here surprisingly from left to right
        stream.write(strxor(self.rnda[2:8], self.rndb[0:6]))  # [ (RndA[13:8] ⊕ RndB[15:10]) ]
        # and back from right to left
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

        c = CMAC.new(b"\x00" * 16, ciphermod=AES)
        c.update(sv1)
        k_ses_auth_enc = c.digest()

        c = CMAC.new(b"\x00" * 16, ciphermod=AES)
        c.update(sv2)
        k_ses_auth_mac = c.digest()

        return ti, pdcap2, pcdcap2, k_ses_auth_enc, k_ses_auth_mac


if __name__ == "__main__":
    auth = AuthenticateEV2()
    auth.generate_rnda = lambda: b"\x13\xC5\xDB\x8A\x59\x30\x43\x9F\xC3\xDE\xF9\xA4\xC6\x75\x36\x0F"

    resp = auth.part1(b"\xA0\x4C\x12\x42\x13\xC1\x86\xF2\x23\x99\xD3\x3A\xC2\xA3\x02\x15\x91\xAF")
    assert resp == binascii.unhexlify("90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00")

    ti, pdcap2, pcdcap2, k_ses_auth_enc, k_ses_auth_mac = auth.part2(
        b"\x3F\xA6\x4D\xB5\x44\x6D\x1F\x34\xCD\x6E\xA3\x11\x16\x7F\x5E\x49"
        b"\x85\xB8\x96\x90\xC0\x4A\x05\xF1\x7F\xA7\xAB\x2F\x08\x12\x06\x63"
        b"\x91\x00")
    assert ti == binascii.unhexlify("9d00c4df")
    assert pdcap2 == binascii.unhexlify("000000000000")
    assert pcdcap2 == binascii.unhexlify("000000000000")
    assert k_ses_auth_enc == binascii.unhexlify("1309C877509E5A215007FF0ED19CA564")
    assert k_ses_auth_mac == binascii.unhexlify("4C6626F5E72EA694202139295C7A7FC7")
