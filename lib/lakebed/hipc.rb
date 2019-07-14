require "stringio"
require_relative "sync.rb"

module Lakebed
  module HIPC
    class Port
      def initialize(name, max_sessions)
        @name = name
        @sessions = []
        @max_sessions = max_sessions
        @client = Client.new(self)
        @server = Server.new(self)
        @pending_connections = Queue.new
      end

      def inspect
        "Port(#{@name}, max = #{@max_sessions})"
      end

      attr_accessor :sessions
      attr_reader :max_sessions
      attr_reader :client
      attr_reader :server
      attr_reader :pending_connections
      
      def connect
        session = Session.new
        @pending_connections.push(session)
        server.signal
        session
      end
      
      class Client < Waitable
        def initialize(port)
          super()
          @port = port
        end

        def is_signaled?
          (@port.sessions.length + @port.pending_connections.length) < @port.max_sessions
        end

        def connect
          @port.connect.client
        end
      end

      class Server < Waitable
        def initialize(port)
          super()
          @port = port
        end

        def is_signaled?
          !@port.pending_connections.empty?
        end

        def accept
          if @port.pending_connections.empty? then
            raise ResultError.new(0xf201)
          end
          session = @port.pending_connections.pop
          session.accept
          @port.sessions.push(session)
          session.server
        end
      end
    end

    class Session
      def initialize
        @client = Client.new(self)
        @server = Server.new(self)
        @accepted = false
        @closed = false
        @pending_requests = Queue.new
      end

      def inspect
        "Session"
      end

      def accept
        @accepted = true
      end
      
      def closed?
        @closed
      end

      def close
        @closed = true
        while !@pending_requests.empty? do
          @pending_requests.pop[:block].call(nil)
        end
        @server.signal
      end
      
      attr_reader :client
      attr_reader :server
      attr_reader :accepted
      attr_reader :closed
      attr_reader :pending_requests

      class Client
        def initialize(session)
          @session = session
        end

        def send_message(msg, &block)
          @session.pending_requests.push(
            {
              :msg => msg,
              :block => block})
          @session.server.signal
        end
      end

      class Server < Waitable
        def initialize(session)
          super()
          @session = session
          @current_reception = nil
        end

        def is_signaled?
          @session.closed? || !@session.pending_requests.empty?
        end

        def close
          @session.close
        end

        def closed?
          @session.closed?
        end
        
        def receive_message(process, buffer, addr)
          if @current_reception != nil then
            raise "attempted to receive a message before replying"
          end
          rq = @session.pending_requests.pop
          @current_reception = rq[:msg].receive(process, buffer, addr, rq[:block])
        end

        def reply_message(process, buffer, size)
          StringIO.open(process.mu.mem_read(buffer, size)) do |msg|
            h1, h2 = msg.read(8).unpack("L<L<")
            if h2[31] == 1 then
              handle_descriptor = {}
              h = msg.read(4).unpack("L<")[0]
              if h[0] == 1 then
                handle_descriptor[:pid] = msg.read(8).unpack("Q<")[0]
                handle_descriptor[:pid] = process.pid
                # TODO: ams pid spoofing
              end
              copy_handles = msg.read(4 * ((h >> 1) & 0xf)).unpack("L<*")
              move_handles = msg.read(4 * ((h >> 5) & 0xf)).unpack("L<*")
              handle_descriptor[:copy_handles] = copy_handles.map do |h|
                process.handle_table.get_strict(h, nil, true, true)
              end
              handle_descriptor[:move_handles] = move_handles.map do |h|
                process.handle_table.get_strict(h, nil, true, true)
                # TODO: remove from source process handle table?
              end
            else
              handle_descriptor = nil
            end

            raw_data_misalignment = msg.pos & 0xf
            raw_data = msg.read(4 * (h2 & 0x3ff))
            
            @current_reception.reply(
              Message.new(
                :type => h1 & 0xffff,
                :handle_descriptor => handle_descriptor,
                :x_descriptors => [],
                :a_descriptors => [],
                :b_descriptors => [],
                :w_descriptors => [],
                :raw_data_misalignment => raw_data_misalignment,
                :raw_data => raw_data,
                :c_descriptors => []
              ))
            @current_reception = nil
          end
        end
      end
    end

    class Message
      def initialize(fields)
        @type = fields[:type]
        @handle_descriptor = fields[:handle_descriptor]
        @x_descriptors = fields[:x_descriptors]
        @a_descriptors = fields[:a_descriptors]
        @b_descriptors = fields[:b_descriptors]
        @w_descriptors = fields[:w_descriptors]
        @raw_data_misalignment = fields[:raw_data_misalignment]
        @raw_data = fields[:raw_data]
        @c_descriptors = fields[:c_descriptors]
      end

      attr_reader :type
      attr_reader :handle_descriptor
      attr_reader :x_descriptors
      attr_reader :a_descriptors
      attr_reader :b_descriptors
      attr_reader :w_descriptors
      attr_reader :raw_data_misalignment
      attr_reader :raw_data
      attr_reader :c_descriptors
      
      # track buffer mappings...
      class Reception
        def initialize(msg, process, block)
          @msg = msg
          @process = process
          @block = block
        end

        def reply(msg)
          # TODO: unmap buffers
          @block.call(msg)
        end
      end
      
      # serialize message back into process
      def receive(proc, addr, size, block)
        h1 = @type & 0xffff
        # TODO: x descriptors
        # TODO: a descriptors
        # TODO: b descriptors
        # TODO: w descriptors
        if @raw_data.size & 0x3 != 0 then
          raise "invalid raw data size"
        end
        h2 = (@raw_data.size / 4) & 0x3ff
        # TODO: c descriptors
        h2|= @handle_descriptor == nil ? 0 : 1 << 31

        message = [h1, h2].pack("L<L<")
        if @handle_descriptor then
          h = 0
          h|= 1 if @handle_descriptor[:pid] != nil
          if @handle_descriptor[:copy_handles].size > 15 then
            raise "too many copy handles"
          end
          if @handle_descriptor[:move_handles].size > 15 then
            raise "too many move handles"
          end
          copy_handles = @handle_descriptor[:copy_handles].map do |object|
            proc.handle_table.insert(object)
          end
          move_handles = @handle_descriptor[:move_handles].map do |object|
            proc.handle_table.insert(object)
          end
          h|= copy_handles.size << 1
          h|= move_handles.size << 5
          message+= [h].pack("L<")
          if @handle_descriptor[:pid] then
            message+= [@handle_descriptor[:pid]].pack("Q<")
          end
          message+= (copy_handles + move_handles).pack("L<*")
        end

        # TODO: buffer descriptors

        if @raw_data_misalignment != message.bytesize & 0xf then
          raise "incorrect raw data misalignment"
        end
        message+= @raw_data

        # TODO: c descriptors

        if message.bytesize > size then
          raise "serialized message too long"
        end
        
        proc.mu.mem_write(addr, message)

        Reception.new(self, proc, block)
      end
    end
  end
end
