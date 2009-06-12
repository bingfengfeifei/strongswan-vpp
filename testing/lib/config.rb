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

require 'ostruct'

require 'kernel_config'
require 'strongswan_config'
require 'guest_config'

module Dumm
  class Config

    # Creates a new Config instance, initialized with the values
    # loaded from the config file.
    def initialize(file)
      @config = read_config(file)
      @kernels = prepare_kernels
      @strongswan = prepare_strongswan
      @guests = prepare_guests
    end

    # Return all strongSwan configurations that are referenced by any guest.
    def strongswan
      @strongswan.select do |name, strongswan|
        @guests.any? { |name, guest| strongswan.eql? guest.strongswan }
      end
    end

    # Return all kernel configurations that are referenced by any guest.
    def kernels
      @kernels.select do |name, kernel|
        @guests.any? { |name, guest| kernel.eql? guest.kernel }
      end
    end

    # Return all valid guest configurations.
    def guests
      @guests.reject { |name, guest| guest.invalid }
    end

  private

    # Reads the config file. The file is processed with ERB before being
    # loaded by YAML and converted into an OpenStruct.
    def read_config(file)
      require 'yaml'
      require 'erb'
      OpenStruct.new(YAML::load(ERB.new(IO.read(file)).result))
    end

    # Initializes the kernel configurations.
    def prepare_kernels
      @config.kernels ||= []
      @kernels = @config.kernels.inject({}) do |h, conf|
        name, conf = *conf
        h[name] = KernelConfig.new name, OpenStruct.new(conf)
        h
      end
    end

    # Initializes the strongswan configurations.
    def prepare_strongswan
      @config.strongswan ||= []
      @strongswan = @config.strongswan.inject({}) do |h, conf|
        name, conf = *conf
        h[name] = StrongswanConfig.new name, OpenStruct.new(conf)
        h
      end
    end

    # Initializes the guest configurations.
    def prepare_guests
      guests = OpenStruct.new @config.guests
      defaults = read_guest_config("guests_defaults", guests.defaults)
      guests.hosts ||= []
      @guests = guests.hosts.inject({}) do |h, conf|
        name, conf = conf.is_a?(Hash) ? conf.shift : [conf, {}]
        conf = read_guest_config("guests_#{name}", conf).delete_if { |k, v| v == nil }
        conf = defaults.merge(conf)
        h[name] = GuestConfig.new name, OpenStruct.new(conf)
        h
      end
    end

    # Read a guest config and return it as Hash.
    def read_guest_config(name, config)
      c = OpenStruct.new config
      h = OpenStruct.new
      h.strongswan = if c.strongswan && c.strongswan.is_a?(Hash)
                       @strongswan[name] = StrongswanConfig.new name, c.strongswan
                     else
                       @strongswan[c.strongswan]
                     end
      h.kernel = if c.kernel && c.kernel.is_a?(Hash)
                   @kernels[name] = KernelConfig.new name, c.kernel
                 else
                   @kernels[c.kernel]
                 end
      c.masterfs = File.expand_path(c.masterfs) if c.masterfs
      h.masterfs = c.masterfs if c.masterfs && (Testing.tarball?(c.masterfs) || File.directory?(c.masterfs))
      c.templates = File.expand_path(c.templates) if c.templates
      h.templates = c.templates if c.templates && File.directory?(c.templates)
      h.mem = c.mem.to_i if c.mem
      h.consoles = c.consoles.select { |c| c =~ /^(xterm|pts)$/ } if c.consoles
      h.marshal_dump
    end

  end
end
