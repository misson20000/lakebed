require "rspec/expectations"
require_relative "lakebed"

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

RSpec::Matchers.define :read_from do |address, match_size|
  if match_size == nil then
    match_size = 8
  end
  match do |emu|
    @read_size = nil
    proc = Proc.new do |uc, access, address, size, value|
      @read_size = size
      emu.mu.emu_stop
    end # keep this in a local variable since unicorn gem doesn't do GC right...

    hook = emu.mu.hook_add(UnicornEngine::UC_HOOK_MEM_READ, proc, nil, address, address + match_size - 1)
    emu.begin
    emu.mu.hook_del(hook)

    @pc = emu.pc
    
    return @read_size == match_size
  end
  failure_message do |actual|
    first_line = "expected that emulator would read 0x#{match_size.to_s(16)} bytes from 0x#{address.to_s(16)}"
    if @read_size then
      second_line = "read: #{@read_value.unpack("H*").first}"
    else
      second_line = "stuck at 0x#{@pc.to_s(16)}"
    end
    return first_line + "\n     " + second_line
  end
end

# my solution to the halting problem :P
RSpec::Matchers.define :infinite_loop do |parameters|
  match do |emu|
    @limit = (parameters && parameters[:after]) || 1000
    emu.begin(@limit)

    @pc = emu.pc

    return emu.mu.mem_read(@pc, 4) == "\x00\x00\x00\x14" # b .
  end
  failure_message do |actual|
    "expected that emulator would hang after #{@limit} instructions"
  end
end

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
