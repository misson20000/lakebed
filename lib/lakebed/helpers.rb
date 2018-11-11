require_relative "matchers/write_to"
require_relative "matchers/read_from"
require_relative "matchers/halt"
require_relative "matchers/call_svc"

module Lakebed
  def self.configure(config)
    config.include Matchers
    
    config.before(:example) do
      @lakebed_expectations = []
    end
    config.after(:example) do
      @lakebed_expectations.each do |e|
        e.verify
      end
    end
  end
end
