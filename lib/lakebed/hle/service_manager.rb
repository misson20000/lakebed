require "pry"

require_relative "cmif_server.rb"

module Lakebed
  module HLE
    class ServiceManager
      def initialize(kernel)
        @kernel = kernel
        @server = CMIF::Server.new

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
      
      class IUserInterface < CMIF::Object
        def initialize(sm)
          @sm = sm
          @initialized = false
        end

        def require_initialization
          if !@initialized && !@sm.vulnerable_to_smhax? then
            raise ResultError.new(0x415)
          end
        end
        
        command(
          0, :Initialize,
          CMIF::In::Pid.new,
          CMIF::In::RawData.new(8, "Q<")) do |pid, _|
          @initialized = true
        end

        command(
          1, :GetService,
          CMIF::In::RawData.new(8, nil, 8, "service"),
          CMIF::Out::Handle.new(:move)) do |service_name|
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

        command(
          2, :RegisterService,
          CMIF::In::RawData.new(8),
          CMIF::In::RawData.new(1, "C"),
          CMIF::In::RawData.new(4, "L<"),
          CMIF::Out::Handle.new(:move)) do |service_name, is_light, max_sessions|
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

        command(
          3, :UnregisterService,
          CMIF::In::RawData.new(8)) do |service_name|
          require_initialization

          if !@sm.services[service_name] then
            raise ResultError.new(0xe15)
          end
          
          s = @sm.services[service_name]
          s.close
          @sm.services.delete(service_name)
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
