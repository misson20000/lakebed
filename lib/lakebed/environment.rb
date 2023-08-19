module Lakebed
  class Environment
    def initialize(target_firmware, ams, master_key_rev)
      @target_firmware = target_firmware
      @ams_version = ams
      @master_key_rev = master_key_rev
    end

    def is_ams?
      @ams_version != nil
    end

    def tipc_enabled?
      true
    end
    
    attr_reader :target_firmware
    attr_reader :ams_version
    attr_reader :master_key_rev
  end
end
