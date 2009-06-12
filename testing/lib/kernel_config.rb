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
  class KernelConfig
    # The name of this kernel
    attr_reader :name
    # The path to the kernel
    attr_reader :path

    # Creates a new Kernel instance from the given configuration
    def initialize(name, config)
      @name = name
      @needs_build = true
      @source = (config.source || "none").to_sym
      config.path = File.expand_path(config.path) if config.path
      config.config = File.expand_path(config.config) if config.config
      @config = config.config if File.file?(config.config || "")
      config.patches ||= []
      @patches = config.patches.map { |p| File.expand_path(p) }.select{ |p|
                   File.exists?(p) && p =~ /\.patch(\.(bz2|gz))?$/ }
      case @source
      when :git, :dir
        unless File.directory?(config.path)
          raise "Path '#{config.path}' not found!"
        end
        @source_path = config.path
        unless @source == :dir
          raise "'#{@source_path} is not a git repository!" unless Testing.git?(@source_path)
          @treeish = config.treeish if Testing.git_tree?(@source_path, config.treeish)
        end
      when :tar
        raise "Tarball '#{config.path}' not found!" unless Testing.tarball?(config.path)
        @source_path = config.path
      else
        raise "Kernel '#{config.path}' not found!" unless File.executable?(config.path)
        @path = config.path
        @needs_build = false
      end
    end

    # Build the kernel.
    def build
      return unless @needs_build
      build_path = @source_path
      case @source
      when :git
        if @treeish
          tarball = Testing.archive_git(@source_path, @treeish, "kernel-#{@name}", Testing.build_dir)
          build_path = Testing.extract_tarball(tarball, Testing.build_dir)
        end
      when :tar
        build_path = Testing.extract_tarball(@source_path, Testing.build_dir)
      end

      apply_patches(build_path)
      ensure_config(build_path)
      @path = File.join(Testing.build_dir, "kernel-#{name}-linux")
      build_kernel(build_path, @path)

      # TODO we could remove the directory extracted from a tarball and the
      # tarball itself if it was exported from git.

      @needs_build = false
    end

  private

    # Apply a list of patches to the given source tree.
    def apply_patches(dir)
      Dir.chdir(dir) do
        @patches.each do |patch|
          comp = case patch
                   when /\.bz2$/: 'bz'
                   when /\.gz$/: 'z'
                   else ''
                 end
          `#{comp}cat #{patch} | patch -p1 2>&1`
          unless $?.success?
            raise "Failed to apply patch '#{patch}' in '#{dir}'!"
          end
        end
      end
    end

    # Ensure that we have a kernel config. Either set in the configuration
    # or found in the given dir.
    def ensure_config(dir)
      config = File.join(dir, ".config")
      @config ||= config
      raise "No kernel config found!" unless File.file?(@config)
      FileUtils.copy_file(@config, config)
    end

    # Build the kernel and move it to the given location.
    def build_kernel(dir, kernel)
      Dir.chdir(dir) do
        # TODO what about logging and error handling
        `make clean ARCH=um 2>&1`
        # the next command might interact with the user. since '`' redirects
        # stdout we would have to use 'system'. currently we use 'yes' to
        # chose the default value for new kernel options.
        `yes "" | make oldconfig ARCH=um 2>&1`
        `make -j 2 linux ARCH=um 2>&1`
        FileUtils.mv 'linux', kernel
      end
    end

  end
end
