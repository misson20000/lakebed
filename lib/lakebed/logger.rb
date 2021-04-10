require "paint"

module Lakebed
  module Logger
    def self.log(msg)
      puts msg
    end

    THREAD_COL_WIDTH = 20

    def self.log_context_switch(a, b)
      puts "[" + Paint[b.to_s.ljust(THREAD_COL_WIDTH), :yellow, :bright] + "] " + Paint["CONTEXT SWITCH", :yellow]
    end
    
    def self.log_for_thread(thread, msg, params={})
      indent = " " * (THREAD_COL_WIDTH + 3)
      msg = msg.lines.join(indent)

      if params.length != 0 then
        msg+= ": "
        msg+= params.map do |k, v|
          ":" + k.to_s + " => " + v.to_s
        end.join(", ")
      end
      
      if @thread != thread then
        puts Paint["[#{thread.to_s.ljust(THREAD_COL_WIDTH)}] ", :gray] + msg
      else
        puts indent + msg
      end
      @thread = thread
    end
  end
end
