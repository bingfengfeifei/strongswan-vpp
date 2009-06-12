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
  class StrongswanConfig
    # The name of this strongSwan config.
    attr_reader :name

    def initialize(name, config)
      @name = name
      @needs_build = true
      @options = config.options
      @source = (config.source || "none").to_sym
      case @source
      when :git, :dir
        unless File.directory?(config.path)
          raise "Path '#{config.path}' not found!"
        end
        @source_path = config.path
        unless @source == :dir
          raise "'#{@source_path} is not a git repository!" unless Testing.git?(@source_path)
          @checkout = config.checkout if Testing.git_tree?(@source_path, config.checkout)
        end
      when :tar
        raise "Tarball '#{config.path}' not found!" unless Testing.tarball?(config.path)
        @source_path = config.path
      else
        raise "Specify the source type of strongSwan config '#{name}'"
      end
    end

    # Build the strongSwan sources. We build them only within the source tree
    # if we extracted the sources from a tarball. Otherwise an out-of-tree build
    # in a subdir of the testing build dir is done.
    def build
      return unless @needs_build
      @build_path = File.join(Testing.build_dir, "strongswan-#{name}")
      case @source
      when :git
        if @checkout
          tarball = Testing.archive_git(@source_path, @checkout, "strongswan-#{@name}", Testing.build_dir)
          @source_path = @build_path = Testing.extract_tarball(tarball, Testing.build_dir)
        end
      when :tar
        @source_path = @build_path = Testing.extract_tarball(@source_path, Testing.build_dir)
      end

      FileUtils.mkdir_p(@build_path)
      configure(@source_path, @build_path)
      make(@build_path)

      @needs_build = false
    end

    def install(target)
      Dir.chdir(@build_path) do
        `make install DESTDIR="#{target}" 2>&1`
        raise "Failed to install strongSwan '#{name}'!" unless $?.success?
        # FIXME is ldconfig required? how do we run this
      end
    end

  private

    # Run the configure script located in directory 'sources' within the
    # directory given as 'build'. autogen.sh is run if configure does not yet
    # exist.
    def configure(sources, build)
      script = File.join(sources, "configure")
      unless File.executable?(script)
        Dir.chdir(sources) do
          `./autogen.sh 2>&1`
          raise "Failed to build configure script for strongSwan '#{name}'!" unless $?.success?
        end
      end
      options = [ '--sysconfdir=/etc', '--with-random-device=/dev/urandom' ]
      @options.each do |opt|
        key, val = opt.shift
        options << "--#{val ? 'enable' : 'disable'}-#{key.sub(/_/, '-')}"
      end
      Dir.chdir(build) do
        `#{script} #{options.join(" ")} 2>&1`
        raise "Failed to configure strongSwan '#{name}'!" unless $?.success?
      end
    end

    # Build the strongSwan sources.
    def make(build)
      Dir.chdir(build) do
        `make -j 2>&1`
        raise "Failed to build strongSwan '#{name}'!" unless $?.success?
      end
    end

  end
end
