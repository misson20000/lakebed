require_relative "cmif_server.rb"
require_relative "service_manager.rb"

module Lakebed
  module HLE
    class SPL
      def initialize(kernel)
        @kernel = kernel

        sm = @kernel.get_hle_module(Lakebed::HLE::ServiceManager)
        
        @server = CMIF::Server.new
        @server.add_port(sm.register_for_hle("spl:")) do
          IGeneralInterface.new(self)
        end
      end

      attr_reader :kernel
      
      class IGeneralInterface < CMIF::Object
        def initialize(spl)
          @spl = spl
        end

        command(
          0, :GetConfig,
          CMIF::In::RawData.new(8, "Q<"),
          CMIF::Out::RawData.new(8, "Q<")) do |item|
          r, v = @spl.kernel.secure_monitor.call(nil, SmcSubId::GetConfig, [item])
          if !r then
            raise ResultError.new(r)
          end
          v
        end
      end
    end
  end
end
