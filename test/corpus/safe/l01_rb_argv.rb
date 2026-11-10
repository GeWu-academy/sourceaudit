require 'open3'
def ping(host)
  Open3.capture2('ping', '-c', '1', host)
end
