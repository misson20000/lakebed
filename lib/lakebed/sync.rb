module Lakebed
  class Waitable
    def initialize
      @waiting_procs = []
    end
    
    def wait(&proc)
      if is_signaled? then
        proc.call
      else
        @waiting_procs.push(proc)
      end
      return proc
    end
    
    def unwait(proc)
      @waiting_procs.delete(proc)
    end
    
    def signal
      if is_signaled? then
        @waiting_procs.each do |p|
          p.call
        end
        @waiting_procs = []
      end
    end
  end
end
