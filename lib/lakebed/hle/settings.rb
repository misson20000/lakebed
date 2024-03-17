require_relative "hle_service.rb"

module Lakebed
  module HLE
    class SettingsServer < HLEService
      def initialize(kernel, extras={})
        super(kernel)

        @fwdbg_settings = {}
        
        if extras[:fwdbg_settings_path] then
          File.open(extras[:fwdbg_settings_path]) do |f|
            file_size = f.read(4).unpack("L<")[0]
            while(f.pos < file_size) do
              setting_length = f.read(4).unpack("L<")[0]
              setting_name = f.read(setting_length)[0, setting_length-1]
              type = f.read(1).unpack("C")[0]
              binary_length = f.read(4).unpack("L<")[0]
              binary_value = f.read(binary_length)

              parts = setting_name.split("!")
              @fwdbg_settings[parts[0]]||= {}
              @fwdbg_settings[parts[0]][parts[1]] = {:type => type, :value => binary_value}
            end
          end
        end
      end

      def inspect
        "SettingsServer"
      end
      
      def register_services
        register("set:cal") do
          IFactorySettingsServer.new
        end

        register("set:sys") do
          ISystemSettingsServer.new(self)
        end
      end

      attr_reader :fwdbg_settings
      
      class IFactorySettingsServer < CMIF::Object
        command(
          16, :GetSslKey,
          CMIF::Buffer.new(0x16, "key", 0x130)) do |output|
          output.write([0x0].pack("C") * output.size)
        end
        
        command(
          17, :GetSslCertificate,
          CMIF::Buffer.new(0x16, "key", 0x130)) do |output|
          output.write([0x0].pack("C") * output.size)
        end
      end

      class ISystemSettingsServer < CMIF::Object
        def initialize(server)
          @server = server
        end
        
        command(
          2, :GetNetworkSettings,
          CMIF::Out::RawData.new(4, "L<"),
          CMIF::Buffer.new(6)) do |buffer|
          0
        end

        command(
          38, :GetSettingsItemValue,
          CMIF::Buffer.new(0x19, "group"),
          CMIF::Buffer.new(0x19, "setting"),
          CMIF::Out::RawData.new(8, "Q<"),
          CMIF::Buffer.new(0x6, "output")) do |group, setting, output|
          group = group.content.unpack("Z128")[0]
          setting = setting.content.unpack("Z128")[0]
          if @server.fwdbg_settings[group] == nil then
            raise "no such fwdbg setting group: " + group
          end

          entry = @server.fwdbg_settings[group][setting]
          
          if entry == nil then
            raise "no such fwdbg setting: " + group + "!" + setting
          end

          output.write(entry[:value])
          entry[:value].bytesize
        end

        command(
          73, :GetWirelessLanEnableFlag,
          CMIF::Out::RawData.new(1, "C")) do
          0
        end
      end
    end
  end
end
