require "pry"

require_relative "cmif_server.rb"
require_relative "tipc_server.rb"

module Lakebed
  module HLE
    class ServiceManager
      def initialize(kernel)
        @kernel = kernel
        @server = CMIF::Server.new(kernel.environment)

        user_port = HIPC::Port.new("sm:", 0x40)
        @kernel.named_ports["sm:"] = user_port
        @server.add_port(user_port.server) do
          IUserInterface.new(self)
        end

        manager_port = HIPC::Port.new(nil, 0x40)

        @services = {["sm:m"].pack("a8") => manager_port.client}
        @server.add_port(manager_port.server) do
          IManagerInterface.new(self)
        end
      end

      def vulnerable_to_smhax?
        !@kernel.environment.is_ams? && @kernel.environment.target_firmware.numeric < 201392178
      end

      attr_reader :kernel
      attr_reader :services

      def register_for_hle(name, max=0x40)
        port = HIPC::Port.new(nil, max)
        @services[[name].pack("a8")] = port.client
        port.server
      end

      def get_port(name)
        @services[[name].pack("a8")]
      end
      
      class IUserInterface < TIPC::Object
        def initialize(sm)
          @sm = sm
          @initialized = false
        end

        def require_initialization
          if !@initialized && !@sm.vulnerable_to_smhax? then
            raise ResultError.new(0x415)
          end
        end

        def cmd_initialize_impl(pid)
          @initialized = true
        end

        def cmd_get_service_impl(service_name)
          require_initialization
          if !@sm.services[service_name] then
            raise CMIF::DeferralError.new
          else
            begin
              @sm.services[service_name].connect
            rescue ResultError => e
              if e.code == 0xe01 then
                raise ResultError.new(0x615)
              else
                raise e
              end
            end
          end
        end

        def cmd_register_service_impl(service_name, is_light, max_sessions)
          require_initialization

          if @sm.services[service_name] then
            raise ResultError.new(0x815)
          end
          
          if @sm.kernel.environment.is_ams? && max_sessions < 8 then
            max_sessions = 8
          end
          
          port = HIPC::Port.new(nil, max_sessions)
          @sm.services[service_name] = port.client
          port.server
        end

        def cmd_unregister_service_impl(service_name)
          require_initialization

          if !@sm.services[service_name] then
            raise ResultError.new(0xe15)
          end
          
          s = @sm.services[service_name]
          s.close
          @sm.services.delete(service_name)
        end
        
        command(
          0, :Initialize,
          CMIF::In::Pid.new,
          CMIF::In::RawData.new(8, "Q<")) do |pid, _|
          cmd_initialize_impl(pid)
        end

        command(
          1, :GetService,
          CMIF::In::RawData.new(8, nil, 8, "service"),
          CMIF::Out::Handle.new(:move)) do |service_name|
          cmd_get_service_impl(service_name)
        end

        command(
          2, :RegisterService,
          CMIF::In::RawData.new(8),
          CMIF::In::RawData.new(1, "C"),
          CMIF::In::RawData.new(4, "L<"),
          CMIF::Out::Handle.new(:move)) do |service_name, is_light, max_sessions|
          cmd_register_service_impl(service_name, is_light, max_sessions)
        end

        command(
          3, :UnregisterService,
          CMIF::In::RawData.new(8)) do |service_name|
          cmd_unregister_service_impl(service_name)
        end

        tipc_command(
          0, :RegisterClient) do |de_ctx|
          cmd_initialize_impl(de_ctx.rq.handle_descriptor[:pid])
          HIPC::Message.new(:type => 0x0, :raw_data_misalignment => 8, :raw_data => [0].pack("L<"))
        end

        tipc_command(
          1, :GetService) do |de_ctx|
          handle = cmd_get_service_impl(de_ctx.rq.raw_data)
          HIPC::Message.new(:type => 0x0, :raw_data_misalignment => 0, :raw_data => [0].pack("L<"), :handle_descriptor => {:copy_handles => [], :move_handles => [handle]})
        end

        tipc_command(
          2, :RegisterService) do |de_ctx|
          name, max_sessions, is_light = de_ctx.rq.raw_data.unpack("a8L<C")
          handle = cmd_register_service_impl(name, max_sessions, is_light)
          HIPC::Message.new(:type => 0x0, :raw_data_misalignment => 0, :raw_data => [0].pack("L<"), :handle_descriptor => {:copy_handles => [], :move_handles => [handle]})
        end
      end

      class IManagerInterface < CMIF::Object
        def initialize(sm)
          @sm = sm
        end

        command(
          0, :RegisterProcess,
          CMIF::In::RawData.new(8, "Q<"),
          # TODO: buffers
        ) do |pid|
        end

        command(
          1, :UnregisterProcess,
          CMIF::In::RawData.new(8, "Q<")) do |pid|
        end
      end
    end
  end
end
