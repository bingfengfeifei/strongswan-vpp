=begin
  Copyright (C) 2009 Tobias Brunner
  Hochschule fuer Technik Rapperswil

  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by the
  Free Software Foundation; either version 2 of the License, or (at your
  option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
  for more details.
=end

module Dumm
  class GuestConfig
    # The name of this guest config.
    attr_reader :name
    # The strongSwan config.
    attr_reader :strongswan
    # The kernel config
    attr_reader :kernel
    # The root directory of this guest (i.e. the diff to the master).
    attr_reader :root
    # True if this guest config is invalid
    attr_reader :invalid

    def initialize(name, config)
      @name = name
      @needs_build = true
      @strongswan, @kernel = config.strongswan, config.kernel
      @masterfs, @templates = config.masterfs, config.templates
      @mem, @consoles = config.mem, config.consoles
      unless @strongswan && @kernel && @masterfs && @mem > 0 && @consoles && !@consoles.empty?
        puts "Invalid guest configuration: #{name} #{config.inspect}"
        @invalid = true
      end
    end

    def build
      return unless @needs_build
      args = "mem=#{@mem}M"
      @consoles.each_with_index do |con, i|
        args << " con#{i.next}=#{con}"
      end
      # TODO if the masterfs is a tarball, extract that first
      
      # Creating the guests using Guest.new does not work because the union
      # filesystem doesn't like us copying lots of files to the union directly
      # when it's mounted. So we have to create the guests manually.
      # Dir.chdir(Testing.root) do
      #   Guest.new @name, @kernel.path, @masterfs, args
      # end
      Dir.chdir(Testing.guests_dir) do
        Dir.mkdir(name, 0775)
        Dir.chdir(name) do
          File.symlink(@masterfs, 'master')
          File.symlink(@kernel.path, 'linux')
          Dir.mkdir('diff', 0775)
          Dir.mkdir('union', 0775)
          File.open('args', 'w') { |f| f.write args }
        end
      end
      @root = File.join(Testing.guests_dir, name, 'diff')

      if @templates
        tmpl = File.join(@templates, name)
        if File.directory?(tmpl)
          # '/.' is required to copy the contents of tmpl and not tmpl itself
          FileUtils.cp_r(tmpl + '/.', @root)
        end
      end

      @needs_build = false
    end

  end
end
