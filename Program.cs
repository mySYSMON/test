using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Diagnostics.Eventing.Reader;
using System.Xml;
using System.Text.RegularExpressions;
#pragma warning disable CA1416 
namespace ConsoleApp2
{
    class Program
    {
        public class Thread1
        {
            public static void DoWork()
            {
                Console.WriteLine("getting events");
                var logName = "Microsoft-Windows-Sysmon/Operational";
                var query =
                "*[System[(EventID=1) and " +
                "TimeCreated[timediff(@SystemTime) <= 600000]]]";
                var logQuery = new EventLogQuery(logName,
                PathType.LogName, query);
                var logReader = new EventLogReader(logQuery);
                var eventCounter = 0;
                var records = new List<EventRecord>();
                for (var er = logReader.ReadEvent(); null != er; er = logReader.ReadEvent())
                {
                    records.Add(er);
                    eventCounter++;
                }
                Console.WriteLine(eventCounter + " events");
                Thread.Sleep(2000);

                var tmpstr = "";
                var sha256 = "";
                var singleNslookup = new List<string>();
                for (int i = 0; i < records.Count; i++)
                {
                    tmpstr = records[i].ToXml();
                    //Console.WriteLine(tmpstr.GetType());
                    foreach (var data in tmpstr.Split('<'))
                    {
                        if (data.StartsWith("Data Name='Hashes'>"))
                        {
                            Console.WriteLine(data);
                            sha256 = data.Substring(data.IndexOf("SHA256=")+7,64);
                            Console.WriteLine(sha256);
                            if (!singleNslookup.Contains(sha256))
                            {
                                singleNslookup.Add(sha256);
                                Process p = new Process();
                                p.StartInfo.FileName = "nslookup.exe";   //sending to locked down receive only pi-hole.  Expect no response.
                                //p.StartInfo.CreateNoWindow = true;
                                p.StartInfo.Arguments = sha256 + " 127.0.0.1";
                                p.StartInfo.UseShellExecute = false;
                                p.Start();
                                //Thread.Sleep(400);
                                //p.Kill();
                            }


                        }
                    }
                    //Thread.Sleep(15000);

                }
                Console.WriteLine(singleNslookup.Count);

            }
        }
        static void Main(string[] args)
        {
            var p = Process.GetCurrentProcess();
            p.PriorityClass = ProcessPriorityClass.BelowNormal;
            Console.WriteLine("Priority is set to: " + p.PriorityClass);
            var thread1 = new Thread(Thread1.DoWork);
            thread1.Start();
            //Console.ReadLine();
        }
    }
}
