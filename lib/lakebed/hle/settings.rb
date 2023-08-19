require_relative "hle_service.rb"

module Lakebed
  module HLE
    class SettingsServer < HLEService
      def register_services
        register("set:cal") do
          IFactorySettingsServer.new
        end
      end
      
      class IFactorySettingsServer < CMIF::Object
        command(
          16, :GetSslKey,
          CMIF::Buffer.new(0x16, "key", 0x130)) do |output|
          output.write([0x0].pack("C") * 0x138)
        end
        
        command(
          17, :GetSslCertificate,
          CMIF::Buffer.new(0x16, "key", 0x130)) do |output|
          output.write([0x0].pack("C") * 0x138)
        end
      end
    end
  end
end
