require_relative "hle_service.rb"

module Lakebed
  module HLE
    class SPL < HLEService
      def register_services
        register("spl:") do
          IGeneralInterface.new(self)
        end
      end
      
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
