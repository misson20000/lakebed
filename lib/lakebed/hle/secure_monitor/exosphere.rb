require_relative "../../constants.rb"

module Lakebed
  module HLE
    module SecureMonitor
      RANDOM_BYTES = ["882be36e3c60cf0a281254ad67f377ce0af02da71b8c62394304b34ce4ab52b12d243c8c0b2b3ffb37aeb57d41f68efd821a9fac1f72a4eb"].pack("H*") # chosen by fair dice roll
      
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
          when SmcSubId::GenerateRandomBytes
            size = args[0]

            puts "SMC generating 0x#{size.to_s(16)} random bytes"

            regs = [0]

            reg_index = 0
            while size >= 8 do
              regs.push(RANDOM_BYTES.byteslice(reg_index*8, 8).unpack("Q<")[0])
              size-= 8
              reg_index+= 1
            end
            
            if size != 0 then
              bytes = RANDOM_BYTES.byteslice(reg_index*8, size).bytes
              value = 0
              bytes.each_with_inex do |b, i|
                value|= (b << (8*i))
              end
              regs.push(value)
            end

            return regs
          else
            raise "unimplemented SMC 0x#{sub_id.to_s(16)}"
          end
        end
      end
    end
  end
end
