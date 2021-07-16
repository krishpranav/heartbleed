#!/usr/bin/env ruby

require 'socket'
require 'openssl'

begin
    port = (ARGV[0] || 4443).to_i
    socket = TCPSocket.new('localhost', port)

rescue OpenSSL::SSL::SSLError
end
