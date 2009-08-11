#!/usr/bin/ruby

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

require 'lib/testing'
require 'fileutils'

include Dumm

# are we running as superuser
unless Process.uid == 0
  puts "Please run #{$0} as superuser!"
  exit 1
end

TESTING_ROOT = File.dirname(__FILE__)

Testing.init

def continue?(msg)
  puts msg
  print "Continue? [Y|n]: "
  if gets.capitalize =~ /^N.*/
    exit 1
  end
end

# cleanup the build dir
build_dir = Testing.build_dir
if File.directory?(build_dir)
  continue?("The existing build directory #{build_dir} will be deleted!")
  FileUtils.remove_entry_secure(build_dir, force = true)
end
FileUtils.mkdir_p(build_dir)

# cleanup the guest dir
guests_dir = Testing.guests_dir
if File.directory?(guests_dir)
  continue?("All guests in #{guests_dir} will be deleted!")
  #Guest.each { |g| g.delete }
  FileUtils.remove_entry_secure(guests_dir, force = true)
end
FileUtils.mkdir_p(guests_dir)

Testing.make

puts "built"

