require "rspec/expectations"

module Lakebed
  module Matchers
    RSpec::Matchers.define :call_svc do |svc_id|
      match do |emu|
        @hit = false
        @matched = true
        
        emu.hook_svc(svc_id) do |svc_id|
          @hit = true
          if @registers then
            @actual_registers = @registers.each_pair.map do |key, value|
              actual = emu.send(key)
              @matched&= (actual == value)
              [key, actual]
            end
          end
          if @mock_return then
            emu.x0 = @mock_return
          else
            emu.call_hle_svc(svc_id)
          end
          emu.mu.emu_stop
        end

        emu.begin

        emu.unhook_svc(svc_id)

        @pc = emu.pc
        
        return @hit && @matched
      end

      chain :with do |registers|
        @registers = registers
      end

      chain :and_return do |return_value|
        @mock_return = return_value
      end

      failure_message do |actual|
        first_line = "expected that emulator would call SVC 0x#{svc_id.to_s(16)} with #{@registers}"
        if @hit then
          second_line = "was actually called with #{@actual_registers}"
        else
          second_line = "was not called (pc 0x#{@pc.to_s(16)})"
        end
        return first_line + "\n     " + second_line
      end
    end

  end
end
