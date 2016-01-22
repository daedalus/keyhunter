#!/usr/bin/python

import binascii
import os
import hashlib
import sys

# bytes to read at a time from file (10meg)
readlength=512

if len(sys.argv)!=2:
  print "./keyhunter.py <filename>"
  exit()

filename = sys.argv[1]

prekeys = ["308201130201010420".decode('hex'), "308201120201010420".decode('hex')]

wif = False


##### start code from pywallet.py #############
__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
  """ encode v, which is a string of bytes, to base58.
  """

  long_value = 0L
  for (i, c) in enumerate(v[::-1]):
    long_value += (256**i) * ord(c)

  result = ''
  while long_value >= __b58base:
    div, mod = divmod(long_value, __b58base)
    result = __b58chars[mod] + result
    long_value = div
  result = __b58chars[long_value] + result

  # Bitcoin does a little leading-zero-compression:
  # leading 0-bytes in the input become leading-1s
  nPad = 0
  for c in v:
    if c == '\0': nPad += 1
    else: break

  return (__b58chars[0]*nPad) + result

def Hash(data):
  return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def EncodeBase58Check(secret):
  hash = Hash(secret)
  return b58encode(secret + hash[0:4])

########## end code from pywallet.py ############


def proc(f,comp):
	prekeys = ["308201130201010420".decode('hex'), "308201120201010420".decode('hex')]
	magic = prekeys[comp]
	magiclen = len(magic)
	# read through target file
	# one block at a time

	lastdata = ""
	rs = 0
	pks = []
	f.seek(0)

	while True:
		data = ""
		data += lastdata
		fdata = f.read(readlength)
		data += fdata

		rs += len(fdata)

  		if len(fdata) == 0:
    			break

  		# look in this block for keys
  		x=0
  		while True:
    			# find the magic number
    			pos=data.find(magic,x)

			if pos > 0:
				hexkey = data[pos+magiclen:pos+magiclen+32]
				pks.append(hexkey)
			else:
				break

    			x+=(pos+1)
  
  		# are we at the end of the file?
  		if len(fdata) < readlength:
    			break

 		 # make sure we didn't miss any keys at the end of the block
  		f.seek(f.tell()-(32+magiclen))
		lastdata = fdata
	
	#print "MByes read:", (rs / (1024**2))

	return pks

# code grabbed from pywallet.py

def print_results(pks,wif,comp):
	pks = sorted(set(pks))

	for pk in pks:
		if wif:
			pk = '\x80' + pk
			if comp == 1:
				pk += "\01"
			print EncodeBase58Check(pk)
		else:
			print binascii.hexlify(pk).zfill(64)


def main():
	f = open(filename)
	pksu = proc(f,0)
	pksc = proc(f,1)
	f.close()
	if wif:
		print_results(pksu + pksc,wif,0)
	else:
		print_results(pksu,wif,0)
		print_results(pksc,wif,1)

main()
