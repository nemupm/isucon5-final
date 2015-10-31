# cd /path/to/isucon5-final/webapp/sql

require 'json'

raw_filename = "initialize.sql"
new_filename = "initialize_subscription.sql"

`rm -f #{new_filename}`
File.open(new_filename, 'w') do |f|
  f.puts "INSERT INTO subscriptions (user_id, ken, ken2, surname, givenname, tenki) VALUES"
end
lines = File.read(raw_filename).split("\n")[10019,10000]
lines.each_with_index do |l|
  id = l[l.index("(")+1..l.index(",")-1]
  print "#{id},"
  json = JSON.parse(l[l.index(",")+3..l.size-4])

  File.open(new_filename, 'a') do |f|
    f.puts "(#{id}, #{json['ken'] ? json['ken']['keys'].first : ''}, #{json['ken2'] ? json['ken2']['params']['zipcode'] : ''}, #{json['surname'] ? "\"" + json['surname']['params']['q'] + "\"" : ''}, #{json['givenname'] ? "\"" + json['givenname']['params']['q'] + "\"": ''}, #{json['tenki'] ? json['tenki']['token'] : ''})" + (id.to_i == lines.size ? ";" : ",")
  end
end
