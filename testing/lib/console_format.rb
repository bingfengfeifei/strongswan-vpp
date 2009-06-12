=begin
  Copyright (C) 2008 Tobias Brunner
  Hochschule fuer Technik Rapperswil

  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by the
  Free Software Foundation; either version 2 of the License, or (at your
  option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
  for more details.

  $Id$
=end

# Simplifies formatting console output by using ANSI escape codes

module Dumm
  module ConsoleFormat
    @@colors = {
      :black => 0,
      :red => 1,
      :green => 2,
      :yellow => 3,
      :blue => 4,
      :magenta => 5,
      :cyan => 6,
      :white => 7
    }
    @@colors.default = 9
    
    @@intensity = { :bold => 1 }
    @@intensity.default = 22
    
    @@blink = { :slow => 5, :rapid => 6 }
    @@blink.default = 25
    
    @@underline = { :single => 4, :double => 21 }
    @@underline.default = 24
    
    @@codes = @@colors.inject({}) { |codes, color|
      codes[color[0]] = 30 + color[1]
      codes[("b#{color[0]}".to_s).to_sym] = 40 + color[1]
      codes
    }
    @@codes = @@codes.merge(@@intensity).merge(@@blink).merge(@@underline)
    @@keywords = @@codes.keys.join("|")
    
    # returns the text either with or without ansi codes wrapped around
    # depending on whether stdout is currently attached to a tty.
    # FIXME: what if we want to write the text to a file i.e. not stdout
    def self.format_text(text, code, force = false)
      STDOUT.isatty || force ? "\e[0#{code}m#{text}\e[0m" : text
    end

    # format is a hash with the following parameters:
    #  - :color: foreground color
    #  - :background: background color
    #  - :intensity: :bold
    #  - :blink: :slow, :rapid
    #  - :underline: :single, :double
    def self.format(text, format = {}, force = false)
      code = ";#{@@blink[format[:blink]]}"
      code += ";#{@@underline[format[:underline]]}"
      code += ";#{@@intensity[format[:intensity]]}"
      code += ";3#{@@colors[format[:color]]}"
      code += ";4#{@@colors[format[:background]]}"
      format_text(text, code, force)
    end
    
    # catches formats of the form:
    #   red_bwhite("red on white")
    #   red_bold("red bold")
    #   red_single("red underline single")
    #   ...
    # background colors start with a 'b'
    def self.method_missing(method, text)
      method = method.to_s
      if method =~ /^(#{@@keywords})(_(#{@@keywords}))*$/
        code = method.split(/_/).inject("") { |c, format|
          c += ";#{@@codes[format.to_sym]}"
        }
        format_text(text, code)
      end
    end
    
    module ConsoleFormatWrapper
      def self.method_missing(method, text)
        ConsoleFormat.__send__ method, text
      end
    end
    
    # global shortcut function 'fmt'
    module ::Kernel
      def fmt(text = nil, format = {}, force = false)
        if text
          ConsoleFormat.format(text, format, force)
        else
          ConsoleFormatWrapper
        end
      end
    end
  end
  
  # Test
  if __FILE__ == $0
    fmt "blank"
    fmt "red", { :color => :red }
    fmt.red_bold "red bold"
    fmt.red_blue_byellow_single_bold "blue on yellow underline single_bold"
    puts ConsoleFormat.format("red", { :color => :red })
    puts ConsoleFormat.format("blue background", { :background => :blue })
    puts ConsoleFormat.format("red on white background", { :color => :red, :background => :white })
    puts ConsoleFormat.format("red bold", { :color => :red, :intensity => :bold })
    puts ConsoleFormat.format("red blink (slow)", { :color => :red, :intensity => :bold, :blink => :slow })
    puts ConsoleFormat.format("red bold blink (rapid)", { :color => :red, :intensity => :bold, :blink => :rapid })
    puts ConsoleFormat.format("green underline single", { :color => :green, :underline => :single })
    puts ConsoleFormat.format("green underline double", { :color => :green, :underline => :double })
    puts ConsoleFormat.red_bold("red bold")
    puts ConsoleFormat.red_bwhite_bold("red on white bold")
    puts ConsoleFormat.red_single("red underline single")
    puts ConsoleFormat.bold_red_single("red underline single bold")
    puts ConsoleFormat.black_bwhite("black on white")
  end
end

