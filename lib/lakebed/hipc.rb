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
        session = Session.new(self)
        @pending_connections.push(session)
        server.signal
        session
      end

      def release_session(sess)
        @sessions.delete(sess)
        @client.signal
      end
      
      class Client < Waitable
        def initialize(port)
          super()
          @port = port
          @closed = false
        end

        attr_reader :port
        attr_reader :closed

        def close
          @closed = true
        end
        
        def is_signaled?
          (@port.sessions.length + @port.pending_connections.length) < @port.max_sessions
        end

        def connect
          if !is_signaled? then
            raise ResultError.new(0xe01, "session count exceeded")
          end
          @port.connect.client
        end
      end

      class Server < Waitable
        def initialize(port)
          super()
          @port = port
        end

        attr_reader :port
        
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
      def initialize(port=nil)
        @client = Client.new(self)
        @server = Server.new(self)
        @accepted = false
        @closed = false
        @pending_requests = Queue.new
        @port = port
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
        if !@closed then
          @closed = true
          while !@pending_requests.empty? do
            @pending_requests.pop[:block].call(nil)
          end
          @server.signal
          if @port then
            # TODO: does this wait for both sides to close?
            @port.release_session(self)
          end
        end
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

        attr_reader :session

        def close
          @session.close
        end

        def describe_message(msg)
          @session.server.describe_message(msg)
        end
        
        def send_message(msg, &block)
          if @session.closed? then
            block.call(nil)
          else
            begin_transaction(Message::Transaction.new(msg, block))
          end
        end
        
        def begin_transaction(transaction)
          @session.pending_requests.push(transaction)
          @session.server.signal
        end
      end

      class Server < Waitable
        def initialize(session)
          super()
          @session = session
          @current_transaction = nil
        end

        attr_reader :session
        
        def is_signaled?
          @session.closed? || !@session.pending_requests.empty?
        end

        def close
          if @current_transaction then
            @current_transaction.close
          end
          @session.close
        end

        def closed?
          @session.closed?
        end

        attr_accessor :message_describer
        
        def describe_message(msg)
          if @message_describer then
            @message_describer.describe_message(msg)
          else
            "unknown"
          end
        end
        
        def receive_message(process, buffer, addr)
          if @current_transaction != nil then
            raise "attempted to receive a message before replying"
          end
          @current_transaction = @session.pending_requests.pop
          @current_transaction.receive(process, buffer, addr)
        end

        def reply_message(process, message)
          @current_transaction.reply(process, message)
          @current_transaction = nil
        end

        def receive_message_for_hle
          if @current_transaction != nil then
            raise "attempted to receive a message before replying"
          end
          @current_transaction = @session.pending_requests.pop
          @current_transaction.rq
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

      def self.parse(process, buffer, size)
        StringIO.open(process.mu.mem_read(buffer, size)) do |msg|
          h1, h2 = msg.read(8).unpack("L<L<")

          # read handle descriptor, if we have one
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

          # read xabw descriptors
          x_descriptors = h1[16..19].times.map do
            x1, x2 = msg.read(8).unpack("L<L<")
            
            addr_high = x1[6..8]
            addr_mid = x1[12..15]
            addr_lo = x2
            size = x1[16..31]
            
            ProcessBufferDescriptor.new(process, addr_lo + (addr_mid << 32) + (addr_high << 36), size)
          end

          a_descriptors = h1[20..23].times.map do
            ProcessBufferDescriptor.parse_abw(process, msg)
          end

          b_descriptors = h1[24..27].times.map do
            ProcessBufferDescriptor.parse_abw(process, msg)
          end

          w_descriptors = h1[28..31].times.map do
            ProcessBufferDescriptor.parse_abw(process, msg)
          end

          raw_data_misalignment = msg.pos & 0xf
          raw_data = msg.read(4 * (h2 & 0x3ff))

          c_descriptor_mode = h2[10..13]

          if c_descriptor_mode == 0 then
            c_descriptors = []
          elsif c_descriptor_mode == 2 then
            raise "TODO: c descriptor mode 2"
          else
            raise "unsupported c descriptor mode: " + c_descriptor_mdoe.to_s
          end
          
          Message.new(
            :type => h1 & 0xffff,
            :handle_descriptor => handle_descriptor,
            :x_descriptors => x_descriptors,
            :a_descriptors => a_descriptors,
            :b_descriptors => b_descriptors,
            :w_descriptors => w_descriptors,
            :raw_data_misalignment => raw_data_misalignment,
            :raw_data => raw_data,
            :c_descriptors => c_descriptors,
          )
        end
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

      class ProcessBufferDescriptor
        def initialize(process, addr, size)
          @process = process
          @addr = addr
          @size = size
        end

        def self.parse_abw(process, msg)
          size_lo, addr_lo, extra = msg.read(12).unpack("L<L<L<")

          flags = extra[0..1]
          addr_high = extra[2..4]
          size_high = extra[24..27]
          addr_mid = extra[28..31]

          ProcessBufferDescriptor.new(process, addr_lo + (addr_mid << 32) + (addr_high << 36), size_lo + (size_high << 32))
        end

        attr_reader :size

        def inspect
          "ProcessBufferDescriptor<\"#{@process.name}\" pid #{@process.pid}, addr 0x#{@addr.to_s(16)}, size 0x#{@size.to_s(16)}>"
        end
        
        def misalignment
          @addr & 0xfff # TODO: how many low bits does kernel preserve?
        end
        
        def read
          @process.mu.mem_read(@addr, @size)
        end

        def write(data)
          if data.bytesize != @size then
            raise "attempt to writeback wrong amount of data"
          end
          @process.mu.mem_write(@addr, data)
        end
      end

      class SyntheticBufferDescriptor
        def initialize(data)
          if data.is_a? String then
            @data = data
            @size = data.bytesize
          elsif data.is_a? Integer then
            @data = 0.chr * data
            @size = data
          else
            raise "invalid argument"
          end
        end

        attr_reader :data
        attr_reader :size

        def misalignment
          0
        end
        
        def read
          @data
        end

        def write(data)
          if data.bytesize != @size then
            raise "attempt to writeback wrong amount of data"
          end
          @data = data
        end
      end
      
      class Transaction
        def initialize(rq, cb)
          @received = false
          @replied = false
          @rq = rq
          @recv_process = nil
          @reply_process = nil
          @cb = cb

          # TODO: grab ReceiveList
        end

        attr_reader :rq
                
        def receive(recv_process, buffer, addr)
          if @received then
            raise "already received transaction"
          end
          @received = true
          @recv_process = recv_process
          @rq.serialize(recv_process, buffer, addr)
          # TODO: read out buffers into server process
        end
        
        def reply(reply_process, rs)
          # NOTE: receive_message_for_hle does not set recv_process
          # because HLE modules don't have processes.
          if @replied then
            raise "alread replied to transaction"
          end
          @replied = true
          @reply_process = reply_process
          
          # TODO: writeback to request buffer descriptors from reply_process
          # TODO: unmap MapAlias buffers from recv_process
          @cb.call(rs)
        end

        def close
          @cb.call(nil)
        end
      end
      
      # serialize message back into process
      def serialize(proc, addr, size)
        h1 = @type & 0xffff
        # TODO: x descriptors
        # TODO: a descriptors
        # TODO: b descriptors
        # TODO: w descriptors
        if @raw_data.size & 0x3 != 0 then
          raise "invalid raw data size: #{@raw_data.size}"
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
      end
    end
  end
end
