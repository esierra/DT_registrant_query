require 'openssl'
require 'net/http'
require 'uri'
require 'json'
require 'pp'
require 'date'
require 'socket'      
class DomainToolsSigner
    
  def self.get(username, key, uri)
    timestamp = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    data      = username+timestamp+uri                                             
    digester  = OpenSSL::Digest::Digest.new("sha256") # can be sha1 | sha256
    signature = OpenSSL::HMAC.hexdigest(digester, key, data)
    "api_username=#{username}&signature=#{signature}&timestamp=#{timestamp}"
  end
end

api_username    = 'APINAME';
api_key         = 'APIKEY';
uri             = '/v1/registrant-alert/';
host            = 'api.domaintools.com';
query           = 'query=evil@email.com'
authentication  = DomainToolsSigner.get(api_username,api_key, uri)
puts "http://#{host}#{uri}?#{query}&#{authentication}"

u1       = UDPSocket.new
uri      = URI.parse("http://#{host}#{uri}?#{query}&#{authentication}")
response = Net::HTTP.get_response(uri)
parsed   = JSON.parse response.body

if num_domains < 1 
  abort("Nothing Found")
end

pp parsed

num_domains = parsed["response"]["total"]
registrant  = parsed["response"]["query"]
registrant  = registrant.gsub("@","_at_") #replaces @ in email with _
campaign    = "Campaign Number"
cs1Label    = "Registrant Domain"
cs2Label    = "Registrant Email"
cs3Label    = "Campaign Name"

(0...num_domains).each  do |x|
    t      = Time.new
    time   = t.strftime("%b %d %H:%M:%S")
    domain = parsed["response"]["alerts"][x]["domain"] #returns x domain
    u1.send "#{time} domain_registrant CEF:0|DOMAINTOOLS|SCRIPT|1.0||domain_tools_script|1|cs1=#{domain} cs2=#{registrant} cs3=#{campaign} cs1Label=#{cs1Label} cs2Label=#{cs2Label} cs3Label=#{cs3Label}" , 0, "hostname", 514
    sleep 2
end