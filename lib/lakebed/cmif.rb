require_relative "hipc.rb"

module Lakebed
  module CMIF
    class ClientSessionObject
      def initialize(ksession)
        @ksession = ksession
      end

      def to_hipc(msg)
        # Thankfully we don't care about bitfuckery here. Just predict
        # how long the HIPC descriptors are and use it to align the
        # data and pass off an abstract HIPCMessage to serialize into
        # the destination server's buffer.

        size = 2 # headers

        if msg.has_handle_descriptor?
          size+= 1 # handle descriptor
        end

        if msg.pid != nil
          size+= 2
        end

        size+= msg.copy_handles.size
        size+= msg.move_handles.size

        # TODO: buffer descriptors

        raw_data_misalignment = (size * 4) & 0xf
        pad_before = ((size + 3) & ~3) - size
        raw_data = 0.chr * 4 * pad_before

        raw_data+= msg.magic + [0, msg.cmdid, 0].pack("L<L<L<")
        raw_data+= msg.data
        
        pad_after = 4 - pad_before
        raw_data+= 0.chr * 4 * pad_after
        # TODO: type A lengths

        return HIPC::Message.new(
                 :type => msg.type,
                 :handle_descriptor =>
                 msg.has_handle_descriptor? ?
                   {:pid => msg.pid,
                    :copy_handles => msg.copy_handles,
                    :move_handles => msg.move_handles} :
                   nil,
                 :x_descriptors => [],
                 :a_descriptors => [],
                 :b_descriptors => [],
                 :w_descriptors => [],
                 :raw_data_misalignment => raw_data_misalignment,
                 :raw_data => raw_data,
                 :c_descriptors => [])
      end

      def from_hipc(msg)
        Unpacker.new(msg)
      end

      def send_message(msg)
        @ksession.send_message(to_hipc(msg)) do |reply|
          yield reply ? from_hipc(reply) : nil
        end
      end

      def send_message_sync(kernel, msg, &block)
        cmif_reply = nil
        session_closed = false
        @ksession.send_message(to_hipc(msg)) do |reply|
          if !reply then
            session_closed = true
            next
          end
          # can't return straight out of block without
          # short-circuiting vital svcR&R logic...
          cmif_reply = from_hipc(reply)
        end
        kernel.continue
        if session_closed then
          raise "server closed session (0xf601)"
        end
        if !cmif_reply then
          raise "server did not reply"
        end
        
        if block then
          return cmif_reply.unpack(&block)
        else
          return cmif_reply
        end
      end
    end

    class Unpacker
      def initialize(msg)
        @msg = msg
        @raw_data_offset = (0x10 - msg.raw_data_misalignment) & 0xf
        @fields = {}

        @move_handle_index = 0
        
        if msg.raw_data.byteslice(@raw_data_offset, 4) != "SFCO" then
          raise "invalid response magic"
        end

        @result_code = msg.raw_data.byteslice(@raw_data_offset + 8, 4).unpack("L<")[0]
      end

      attr_reader :result_code

      def move_handle(tag, type=nil)
        if @move_handle_index >= @msg.handle_descriptor[:move_handles].size then
          raise "not enough move handles"
        end
        mh = @msg.handle_descriptor[:move_handles][@move_handle_index]
        
        if type != nil then
          if !mh.is_a?(type) then
            raise "expected a #{type}, got #{mh}"
          end
        end
        
        if tag then
          @fields[tag] = mh
          @move_handle_index+= 1
        end
        mh
      end
      
      def unpack(&block)
        if(@result_code != 0) then
          raise "result (0x#{@result_code.to_s(16)}) was not OK"
        end
        instance_eval(&block)
        @fields
      end
    end
    
    class Message
      def initialize(type, magic, cmdid, pid, copy_handles, move_handles, data, buffers)
        @type = type
        @magic = magic
        @cmdid = cmdid
        @pid = pid
        @copy_handles = copy_handles
        @move_handles = move_handles
        @data = data
        @buffers = buffers
      end

      def has_handle_descriptor?
        @pid != nil || !@copy_handles.empty? || !@move_handles.empty?
      end

      attr_reader :type
      attr_reader :magic
      attr_reader :cmdid
      attr_reader :pid
      attr_reader :copy_handles
      attr_reader :move_handles
      attr_reader :data
      attr_reader :buffers
      
      class MessageBuilder
        def initialize(magic, type, cmdid)
          @magic = magic
          @type = type
          @cmdid = cmdid
          @pid = nil
          @copy_handles = []
          @move_handles = []
          @data = String.new
          @buffers = []
        end

        def to_message
          align(4)
          Message.new(@type, @magic, @cmdid, @pid, @copy_handles, @move_handles, @data, @buffers)
        end

        def type(type)
          @type = type
        end
        
        def pid(pid)
          @pid = pid
          u64(0)
        end
        
        def u64(val)
          align(8)
          @data+= [val].pack("Q<")
        end

        def u32(val)
          align(4)
          @data+= [val].pack("L<")
        end

        def u8(val)
          align(1)
          @data+= [val].pack("C")
        end

        def align(alignment)
          size = @data.bytesize + (alignment - 1)
          size-= size % alignment
          @data+= 0.chr * (size - @data.bytesize)
        end
      end
      
      def self.build_rq(cmdid, &block)
        builder = MessageBuilder.new("SFCI", 4, cmdid)
        builder.instance_eval(&block)
        builder.to_message
      end

      def self.build_rs(code, &block)
        builder = MessageBuilder.new("SFCO", 0, code)
        builder.instance_eval(&block)
        builder.to_message
      end
    end

    module Matchers
      RSpec::Matchers.define :reply_with_error do |expected|
        match do |unpacker|
          return unpacker.result_code == expected
        end

        failure_message do |actual|
          "expected that reply would have error code 0x#{expected.to_s(16)}, got 0x#{actual.result_code.to_s(16)}"
        end
      end

      RSpec::Matchers.define :reply_ok do
        match do |unpacker|
          return unpacker.result_code == 0
        end

        failure_message do |actual|
          "expected that reply would be OK, got 0x#{actual.result_code.to_s(16)} instead"
        end
      end
    end
  end
end
