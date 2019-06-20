require_relative "cmif"

module Lakebed
  def self.configure(config)
    config.include CMIF::Matchers
 end
end
