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
