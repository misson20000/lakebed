module Lakebed
  class LakebedError < StandardError
  end
  
  class GuestExceptionError < LakebedError
    def initialize(proc, message, cause=nil)
      @proc = proc
      @message = message
      @cause = cause
      @pc = proc.pc
      @bt = [@pc, @proc.mu.reg_read(UnicornEngine::UC_ARM64_REG_X30)]
      begin
        fp = @proc.mu.reg_read(UnicornEngine::UC_ARM64_REG_X29)
        while fp != 0 do
          fp, lr = @proc.mu.mem_read(fp, 16).unpack("Q<Q<")
          @bt.push(lr)
        end
      rescue RuntimeError => e
      end
      @regs = 31.times.map do |r|
        @proc.mu.reg_read(UnicornEngine.const_get("UC_ARM64_REG_X" + r.to_s))
      end
      super(message)
    end

    attr_reader :cause
    
    def message
      "#{@message} - BACKTRACE:\n" + @bt.map do |e|
        "  - " + @proc.as_mgr.inspect_addr(e)
      end.join("\n") + "\nREGISTERS:\n" + @regs.each_with_index.map do |r, i|
        "  x#{i.to_s.ljust(2)}: 0x#{r.to_s(16).rjust(16, "0")}"
      end.join("\n")
    end
  end
  
  class InvalidWriteError < GuestExceptionError
    def initialize(proc, value, address)
      super(proc, "attempted to write #{value.unpack("H*").first} to 0x#{address.to_s(16)}")
      @value = value
      @address = address
    end
  end

  class StratosphereAbortError < GuestExceptionError
    def initialize(proc)
      super(proc, "called stratosphere's std::abort")
    end
  end
  
  class UnmappedReadError < GuestExceptionError
    def initialize(proc, size, address)
      super(proc, "attempted to read 0x#{size.to_s(16)} bytes from 0x#{address.to_s(16)}")
      @size = size
      @address = address
    end
  end

  class UnknownSvcError < GuestExceptionError
    def initialize(proc, id)
      super(proc, "attempted to call unknown svc 0x#{id.to_s(16)}")
      @id = id
    end
  end

  class ResultError < LakebedError
    def initialize(code, message=nil)
      if message then
        super("0x" + code.to_s(16) + ": " + message)
      else
        super("0x" + code.to_s(16))
      end
      @code = code
    end

    attr_reader :code
  end

  class TodoError < LakebedError
  end
end
