require_relative "cmif_server.rb"

module Lakebed
  module HLE
    class HLEService
      def initialize(kernel)
        @kernel = kernel
        @server = CMIF::Server.new(kernel.environment)

        @kernel.wait_for_port("sm:") do |port|
          @sm = Lakebed::CMIF::ClientSessionObject.new(port.client.connect)
          @sm.send_message_sync(
            @kernel,
            Lakebed::CMIF::Message.build_rq(0) do
              pid(1)
            end)
          register_services
        end
      end

      attr_reader :kernel
      
      def register_services
        # override me!
      end
      
      def register(name, max_sessions=32, pointer_buffer_size=512, &block)
        port = @sm.send_message_sync(
          @kernel,
          Lakebed::CMIF::Message.build_rq(2) do
            u64([name].pack("a8").unpack("Q<")[0])
            u8(0)
            u32(max_sessions)
          end) do
          move_handle(:port, Lakebed::HIPC::Port::Server)
        end[:port]

        @server.add_port(port, pointer_buffer_size, &block)
      end
    end
  end
end
