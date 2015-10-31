# cd /path/to/isucon5-final/webapp/sql

require 'json'

raw_filename = "initialize.sql"
new_filename = "initialize_subscription.sql"

`rm -f #{new_filename}`
File.open(new_filename, 'w') do |f|
  f.puts "INSERT INTO subscriptions (user_id, ken, ken2, surname, givenname, tenki, perfectsec_req, perfectsec_token, perfectsec_attacked) VALUES"
end
lines = File.read(raw_filename).split("\n")[10019,10000]
lines.each_with_index do |l|
  id = l[l.index("(")+1..l.index(",")-1]
  print "#{id},"
  json = JSON.parse(l[l.index(",")+3..l.size-4])

  ken       = json['ken'] ? "\"" + json['ken']['keys'].first + "\"" : nil
  ken2      = json['ken2'] ? "\"" + json['ken2']['params']['zipcode'] + "\"" : nil
  surname   = json['surname'] ? "\"" + json['surname']['params']['q'] + "\"" : nil
  givenname = json['givenname'] ? "\"" + json['givenname']['params']['q'] + "\"" : nil
  tenki     = json['tenki'] ? "\"" + json['tenki']['token'] + "\"" : nil
  if json['perfectsec']
	perfectsec_req   = "\"" + json['perfectsec']['params']['req'] + "\""
	perfectsec_token = "\"" + json['perfectsec']['token'] + "\""
  end
  perfectsec_attacked = json['perfectsec_attacked'] ? "\"" + json['perfectsec_attacked']['token'] + "\"" : nil

  File.open(new_filename, 'a') do |f|
	  f.puts "(#{id}, #{ken ? ken : "NULL"}, #{ken2 ? ken2 : "NULL"}, #{surname ? surname : "NULL"}, #{givenname ? givenname : "NULL"}, #{tenki ? tenki : "NULL"}, #{perfectsec_req ? perfectsec_req : "NULL"}, #{perfectsec_token ? perfectsec_token : "NULL"}, #{perfectsec_attacked ? perfectsec_attacked : "NULL"})"
  end
end
