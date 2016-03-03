unless String.instance_methods.include?(:wstrip)
  class String
    def wstrip
      self.force_encoding('UTF-16LE').encode('UTF-8',:invalid => :replace, :undef => :replace).
      split("\x00")[0].encode(Encoding.default_external)
    rescue
      nil
    end
  end
end
