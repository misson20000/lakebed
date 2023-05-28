require_relative "hle_service.rb"

module Lakebed
  module HLE
    class SPL < HLEService
      def register_services
        register("spl:") do
          IGeneralInterface.new(self)
        end

        register("spl:ssl") do
          ISslInterface.new(self)
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

      class ISslInterface < CMIF::Object
        def initialize(spl)
          @spl = spl
        end

        command(
          2, :GenerateAesKek,
          CMIF::In::RawData.new(0x10, nil, 0x10, "eks"),
          CMIF::In::RawData.new(0x4, "L<", 0x4, "KeyGeneration"),
          CMIF::In::RawData.new(0x4, "L<", 0x4, "option"),
          CMIF::Out::RawData.new(0x10)) do |eks, kg, opt|
          0.chr * 16
        end
        
        command(
          11, :IsDevelopment,
          CMIF::Out::RawData.new(1, "C")) do
          0
        end

        command(
          13, :DecryptDeviceUniqueData,
          CMIF::In::RawData.new(0x10, nil, 0x10, "access_key"),
          CMIF::In::RawData.new(0x10, nil, 0x10, "key_source"),
          CMIF::In::RawData.new(0x4, "L<", 0x4, "version"),
          CMIF::Buffer.new(0x9),
          CMIF::Buffer.new(0xa)) do |kek, key, version, data_in, data_out|
          data_in.descriptor.process.as_mgr.dump_mappings
          data_out.write(0.chr * 0x100)
          data_out
        end
      end
    end
  end
end
