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

$LOAD_PATH.unshift File.dirname(__FILE__)
require 'config'

module Dumm
  class Testing
    class << self
      # The base directory.
      attr_reader :root
      # The build directory.
      attr_reader :build_dir
      # The guests directory.
      attr_reader :guests_dir
      # The global Config instance
      attr_reader :config

      def init
        set_directories!
        config_file = "#{root}/config/default.yml"
        @config = Config.new(config_file)
      end

      # Create the testing environment.
      def make
        make_kernel
        make_guests
        make_strongswan
      end

      # Check if the given file is a tarball.
      def tarball?(file)
        file && File.file?(file) && file =~ /(\.tar(\.(bz2|gz))?|\.t[bg]z)$/
      end

      # Returns the name of the tarball without extension and path.
      # This is the assumed name of the directory that the tarball extracts to.
      def tarball_name(file)
        file.sub(/^.*\/([^\/]+)(\.tar(\.(bz2|gz))?|\.t[bg]z)$/, '\1')
      end

      # Check the given path for a git repository. If 'tree' is given we check
      # that there exists such a point in the git history.
      def git?(dir)
        return false unless File.directory?(dir)
        Dir.chdir(dir) do
          !`git status`.empty?
        end
      end

      # Check that tree points to a valid point in the history of the git
      # repository (commit, tag, branch).
      def git_tree?(dir, tree)
        return false unless File.directory?(dir)
        Dir.chdir(dir) do
          tree && !tree.empty? && !`git show #{tree}`.empty?
        end
      end

      # Extract the given tarball in directory 'dir'. The tarball is expected
      # to extract into a directory of the same name. Returns the path to the
      # extracted directory.
      # If the expected directory already exists, nothing is done.
      def extract_tarball(file, dir)
        target = File.join(dir, tarball_name(file))
        return target if File.directory?(target)
        Dir.chdir(dir) do
          comp = case file
                   when /\.(bz2|tbz)$/: 'j'
                   when /\.(gz|tgz)$/: 'z'
                   else ''
                 end
          unless system("tar x#{comp}f #{file} 2>&1")
            raise "Failed to extract tarball '#{file}'!"
          end
          unless File.directory?(target)
            raise "Tarball '#{file}' extracted to unexpected directory!"
          end
        end
        target
      end

      # Uses 'git archive' to build a tarball from the git repository in
      # directory 'repo'. 'tree' is the tag, branch or commit from which the
      # archive is built. The tarball is written to 'dir'/'name'.tar and it will
      # extract to a directory named 'name'. The filename of the tarball is
      # returned.
      def archive_git(repo, tree, name, dir)
        target = File.join(dir, "#{name}.tar")
        Dir.chdir(repo) do
          unless system("git archive --format=tar --prefix=#{name}/ #{tree} > #{target}")
            raise "Failed to build archive from git repository '#{git}'!"
          end
        end
        target
      end

    private

      # Sets root to TESTING_ROOT and canonalizes it. Also sets the build
      # and guest dir based on the root.
      def set_directories!
        require 'pathname'
        raise 'TESTING_ROOT is not set' unless defined?(::TESTING_ROOT)
        raise 'TESTING_ROOT is not a directory' unless File.directory?(::TESTING_ROOT)
        @root = Pathname.new(::TESTING_ROOT).realpath.to_s
        ::TESTING_ROOT.replace @root
        @build_dir = File.join(@root, 'build')
        @guests_dir = File.join(@root, 'guests')
      end

      # Build all required kernels.
      def make_kernel
        config.kernels.each do |name, kernel|
          kernel.build
        end
      end

      # Create all the guests.
      def make_guests
        config.guests.each do |name, guest|
          guest.build
        end
      end

      # Build and install all strongSwan versions.
      def make_strongswan
        config.strongswan.each do |name, strongswan|
          strongswan.build
          guests = config.guests.select { |n, g| strongswan.eql? g.strongswan }
          guests.each do |name, guest|
            strongswan.install guest.root
          end
        end
      end

    end
  end
end
