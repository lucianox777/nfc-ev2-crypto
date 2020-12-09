import binascii

from validate_ecc import validate_tag


def test_original1():
  uid = binascii.unhexlify('04518DFAA96180')
  sig = binascii.unhexlify('D1940D17CFEDA4BFF80359AB975F9F6514313E8F90C1D3CAAF5941AD744A1CDF9A83F883CAFE0FE95D1939B1B7E47113993324473B785D21')
  
  assert validate_tag(uid, sig)


def test_original2():
  uid = binascii.unhexlify('12345678901234')
  sig = binascii.unhexlify('D1940D17CFEDA4BFF80359AB975F9F6514313E8F90C1D3CAAF5941AD744A1CDF9A83F883CAFE0FE95D1939B1B7E47113993324473B785D21')
  
  assert not validate_tag(uid, sig)
