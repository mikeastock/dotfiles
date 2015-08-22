require "colorize"
require "rake"

task default: :install

desc "install the dot files into user's home directory"
task :install do
  replace_all = false
  Dir.entries("files/").each do |file|
    next if [".", ".."].include?(file)

    path = File.join(ENV["HOME"], ".#{file}")
    if File.exist?(path) || File.symlink?(path)
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
  puts "linking ~/.#{file}".green
  system %Q{ln -s "$PWD/files/#{file}" "$HOME/.#{file}"}
end

desc "Install dotfiles with relative paths"
task :install_relative do
  Dir.entries("files/").each do |file|
    next if [".", ".."].include?(file)

    puts "linking ~/.#{file}".green
    system %Q{ln -s "./.dotfiles/files/#{file}" "../.#{file}"}
  end
end

task :uninstall do
  Dir.entries("files/").each do |file|
    next if [".", ".."].include?(file)
    system %Q{rm -rf "$HOME/.#{file}"}
  end
end
