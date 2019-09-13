module Lakebed
  class ResourceLimit
    def initialize
      @limits = []
    end
    
    def set_limit_value(resource, value)
      @limits[resource] = value
    end

    def get_limit_value(resource)
      @limits[resource]
    end

    def get_current_value(resource)
      0 # TODO
    end
  end
end
