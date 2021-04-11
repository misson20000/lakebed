require_relative "../../constants.rb"

module Lakebed
  module HLE
    module SecureMonitor
      class Exosphere
        def initialize(environment)
          @environment = environment
        end

        attr_reader :environment

        def call(proc, sub_id, args)
          case sub_id
          when SmcSubId::GetConfig # smc_get_config_user
            case args[0]
            when ConfigItem::DisableProgramVerification
              config = 0
            when ConfigItem::MemoryArrange
              config = 0
            when ConfigItem::ExosphereApiVersion
              config =
                ((@environment.ams_version[0] & 0xff) << 56) |
                ((@environment.ams_version[1] & 0xff) << 48) |
                ((@environment.ams_version[2] & 0xff) << 40) |
                ((@environment.master_key_rev) << 32) | # GetKeyGeneration
                ((@environment.target_firmware.ams_target) << 0) # GetTargetFirmware
            else
              raise "unknown config item #{args[0]}"
            end
            return [0, config]
          else
            raise "unimplemented SMC 0x#{sub_id.to_s(16)}"
          end
        end
      end
    end
  end
end
