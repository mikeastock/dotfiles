require "colorize"
require "rake"

desc "install the dot files into user's home directory"
task :install do
  replace_all = false
  Dir["files/*"].each do |file|
    if File.exist?(File.join(ENV["HOME"], ".#{file}"))
      if replace_all
        replace_file(file)
      else
        print "overwrite ~/.#{file}? [ynaq] ".red
        case $stdin.gets.chomp
        when "a"
          replace_all = true
          replace_file(file)
        when "y"
          replace_file(file)
        when "q"
          exit
        else
          puts "skipping ~/.#{file}".yellow
        end
      end
    else
      link_file(file)
    end
  end

  system %Q{mkdir ~/.tmp}
end

def replace_file(file)
  system %Q{rm "$HOME/.#{file}"}
  link_file(file)
end

def link_file(file)
  puts "linking ~/.#{file}"
  system %Q{ln -s "$PWD/#{file}" "$HOME/.#{file}"}
end
