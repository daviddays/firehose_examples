using System;
using System.Threading;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;
using Newtonsoft.Json.Linq; // requires .NET Core 3.0 or higher, or the NuGet package

namespace SSLClient
{

    public class FlightObject
    {

        public String type { get; set; }
        public String ident { get; set; }
        public String air_ground { get; set; }
        public String alt { get; set; }
        public String clock { get; set; }
        public String id { get; set; }
        public String gs { get; set; }
        public String heading { get; set; }
        public String lat { get; set; }
        public String lon { get; set; }
        public String reg { get; set; }
        public String squawk { get; set; }
        public String updateType { get; set; }


        public String toString()
        {
            String result;
            // format result into 2 columns, left justify data, min 10 chars col space
            result = String.Format(" {0,-10} {1,-10}\n {2,-10} {3,-10}\n {4,-10} {5,-10}\n" +
                                   " {6,-10} {7,-10}\n {8,-10} {9,-10}\n {10,-10} {11,-10}\n" +
                                   " {12,-10} {13,-10}\n {14,-10} {15,-10}\n {16,-10} {17,-10}\n" +
                                   " {18,-10} {19,-10}\n {20,-10} {21,-10}\n {22,-10} {23,-10}\n" +
                                   " {24,-10} {25,-10}\n",
                                   "type", type,
                                   "ident", ident,
                                   "airground", air_ground,
                                   "alt", alt,
                                   "clock", clock,
                                   "id", id,
                                   "gs", gs,
                                   "heading", heading,
                                   "lat", lat,
                                   "lon", lon,
                                   "reg", reg,
                                   "squawk", squawk,
                                   "updateType", updateType
                                  );
            return result;
        }
    }


    public class SSLClient
    {
        public static String username = "XXXXXXXX";
        public static String apikey = "XXXXXXXXXXXXXXXXXXXX";
        public static Boolean useCompression = true;
        public static string eventsList = null;
        public static List<Dictionary<string,string>> records = new List<Dictionary<string, string>>();
        public static String initiation_command => $"live username {username} password {apikey} {(useCompression ? " compression deflate" : "")} optype_filter ga";

        // The following method is invoked by the RemoteCertificateValidationDelegate
        // prevent communication with unauthenticated server
        public static bool ValidateServerCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                // authenticated
                return true;
            }

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);
            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }
        public static void RunClient(string machineName, string serverName)
        {
            // Create a TCP/IP client socket.
            TcpClient client = new TcpClient(machineName, 1501);

            // Create ssl stream to read data
            SslStream sslStream = new SslStream(
                client.GetStream(),
                true,
                new RemoteCertificateValidationCallback(ValidateServerCertificate),
                null);
            try
            {
                // require at least TLS 1.2 (this enumeration exists starting in .NET 4.5)
                // (older platforms use:) var sslProtocols = (SslProtocols)0x00000C00;
                var sslProtocols = SslProtocols.Tls12;

                // server name must match name on the server certificate.
                sslStream.AuthenticateAsClient(serverName, null, sslProtocols, true);
                Console.WriteLine("sslStream AuthenticateAsClient completed.");
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine("Authentication failed - closing the connection.");
                client.Close();
                return;
            }

            // Send initiation command to the server.
            // Encode to a byte array.
            Console.WriteLine(initiation_command);
            string eventsCommand = "";
            if (!string.IsNullOrEmpty(eventsList) && !string.IsNullOrWhiteSpace(eventsList)) {
                Console.WriteLine("requesting the following event info:  "+eventsList);
                eventsCommand = $" events \"{eventsList}\"";
            }
            byte[] messsage = Encoding.UTF8.GetBytes(initiation_command + eventsCommand+ "\n");
            sslStream.Write(messsage);
            sslStream.Flush();

            //read from server, print to console:
            StreamReader sr;
            if (useCompression)
            {
                sr = new StreamReader(new DeflateStream(sslStream, CompressionMode.Decompress));
            }
            else
            {
                sr = new StreamReader(sslStream);
            }
            int limit = 1000;
            while (limit > 0)
            {
                string line;
                if (useCompression)
                {
                    line = sr.ReadLineAsync().Result;
                }
                else
                {
                    line = sr.ReadLine();
                }
                
                if (line == null)
                {
                    limit = 0;
                }
                else
                {
                    Console.WriteLine(" Received: " + line);
                    parse(line);
                    limit--;
                }
                
            }

            // Close the client connection.
            sr.Close();
            client.Close();
            Console.WriteLine("Client closed.");
        }

        public static void parse(string mes) {
            JObject mJson = JObject.Parse(mes);
            Dictionary<string,string> record = new Dictionary<string, string>();
            foreach (var mkey in mJson.Properties()) {
                if (mkey.Name.Equals("waypoints", StringComparison.InvariantCultureIgnoreCase)) {
                    //convert to WKT
                    var wptArr = mkey.Value as JArray;
                    int wptCount = wptArr.Count;
                    string wktType = wptCount > 1 ? "\"LINESTRING" : "\"POINT";
                    StringBuilder wktBuilder = new StringBuilder(wktType);
                    wktBuilder.Append("(");
                    for (int i = 0; i < wptCount; i++) {
                        var llObj = wptArr[i];
                        string lngTxt = String.Empty;
                        string latTxt = String.Empty;
                        if (llObj["lon"] != null) lngTxt = llObj["lon"].ToString();
                        if (llObj["lat"] != null) latTxt = llObj["lat"].ToString();
                        wktBuilder.AppendFormat("{0} {1}", lngTxt, latTxt);
                        if (i < wptCount - 1) wktBuilder.Append(",");
                    }
                    wktBuilder.Append(")\"");
                    record.Add("zzwkt", wktBuilder.ToString());
                } else {
                    record.Add(mkey.Name, mkey.Value.ToString());
                }
            }

            if (record.ContainsKey("lat") && record.ContainsKey("lon") && !record.ContainsKey("flightwkt")) {
                record.Add("zzwkt", $"\"POINT({record["lon"]} {record["lat"]})\"");
            }
            records.Add(record);
        }

        public static void WriteRecords(List<Dictionary<string, string>> records, string fname) {
            StringBuilder sb = new StringBuilder();
            List<string> columns = new List<string>();
            foreach (var rec in records) {
                foreach(string rkey in rec.Keys) columns.Add(rkey);
            }

            string[] columnArr = columns.Distinct().OrderBy(s => s).ToArray();
            using (FileStream of = new FileStream(fname, FileMode.Create)) {
                StringBuilder hdrBuilder = new StringBuilder();
                int lastCol = columnArr.Length - 1;
                for (int i = 0; i < columnArr.Length; i++) {
                    hdrBuilder.Append(columnArr[i]);
                    if (i < lastCol) {
                        hdrBuilder.Append(",");
                    } else {
                        hdrBuilder.AppendLine();
                    }
                }

                of.Write(Encoding.UTF8.GetBytes(hdrBuilder.ToString()));
                of.Flush(true);
                StringBuilder recordBuilder = new StringBuilder();
                foreach (var record in records) {
                    for (int i = 0; i < columnArr.Length; i++) {
                        string col = columnArr[i];
                        if (record.ContainsKey(col)) {
                            recordBuilder.Append(record[col]);
                        } else {
                            recordBuilder.Append(String.Empty);
                        }

                        if (i < lastCol) {
                            recordBuilder.Append(",");
                        } else {
                            recordBuilder.AppendLine();
                        }
                    }
                }
                of.Write(Encoding.UTF8.GetBytes(recordBuilder.ToString()));
                of.Flush(true);
            }
        }

        public static int Main(string[] args)
        {

            if (args == null || args.Length < 2) throw new Exception("[main] username apikey [events list]");
            string eventsListing = null;
            if (args.Length > 2) {
                StringBuilder sb = new StringBuilder();
                for (int i = 2; i < args.Length; i++) {
                    sb.Append(args[i]);
                    if (i < args.Length - 1) sb.Append(" ");
                }

                eventsListing = sb.ToString();
            }
            // machineName is the host running the server application.
            String machineName = "firehose.flightaware.com";
            String serverCertificateName = machineName;

            SSLClient.username = args[0];
            SSLClient.apikey = args[1];
            SSLClient.eventsList = eventsListing;
            //connect, read data
            SSLClient.RunClient(machineName, serverCertificateName);

            WriteRecords(SSLClient.records, $"{eventsListing.Replace(" ","")}.csv");
            Console.WriteLine(" Hit Enter to end ...");
            Console.Read();
            return 0;
        }
    }
}