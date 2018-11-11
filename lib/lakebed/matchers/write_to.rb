require "rspec/expectations"

module Lakebed
  module Matchers
    RSpec::Matchers.define :write_to do |address, value|
      match do |emu|
        @written_value = nil
        proc = Proc.new do |uc, access, address, size, value|
          case size
          when 1
            @written_value = [value].pack("C")
          when 2
            @written_value = [value].pack("S<")
          when 4
            @written_value = [value].pack("L<")
          when 8
            @written_value = [value].pack("Q<")
          else
            raise "unhandled size: #{size}"
          end
          emu.mu.emu_stop
        end # keep this in a local variable since unicorn gem doesn't do GC right...
        hook = emu.mu.hook_add(UnicornEngine::UC_HOOK_MEM_WRITE, proc, nil, address, address + value.size - 1)
        emu.begin
        emu.mu.hook_del(hook)

        @pc = emu.pc
        
        return @written_value == value
      end
      failure_message do |actual|
        first_line = "expected that emulator would write #{value.unpack("H*").first} to 0x#{address.to_s(16)}"
        if @written_value then
          second_line = "wrote #{@written_value.unpack("H*").first} instead"
        else
          second_line = "stuck at #{@pc.to_s(16)}"
        end
        return first_line + "\n     " + second_line
      end
    end
  end
end
