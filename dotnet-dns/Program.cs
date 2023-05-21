namespace DNS_Hackathon_2023;
using System;
using System.Net;
using System.Security.Cryptography;
using DnsClient;

class Program
{
    static void Main(string[] args)
    {
        string hostName = string.Empty;
        IPHostEntry hostInfo = Dns.GetHostEntry(hostName);
        hostName = hostInfo.HostName;
        var client = new LookupClient();

        string parentZone = "zenr.io";
        string newSubZone = "testzone";
        string newZoneServerFQDN = "dns-oarc.free2air.net";
        string newZoneServerIP="128.140.34.230";
        string newZoneContact="root.free2air.org";
        string newZone = string.Join('.',newSubZone, parentZone);
        
        //var newZoneFilePath = System.Environment.SpecialFolder.LocalApplicationData;
        var zoneFilePath = @$"/var/named/dynamic/{newZone}"; 
        var zoneFilePathOwner = "";
        var newZoneFile = @$"named.{newZone}";
        var keyAlgorithm = "RSASHA256";
        var newKey = RSA.Create(2048);

        var dsResult = client.Query(parentZone, QueryType.DS);
        var dnsResult = client.Query(parentZone, QueryType.DNSKEY);
        var nsResult = client.Query(parentZone, QueryType.NS);

        List<IDnsQueryResponse> responses = new List<IDnsQueryResponse>{ dsResult, dnsResult, nsResult};

        // if(!Directory.Exists(zoneFilePath))
        // {
        //     Directory.CreateDirectory(zoneFilePath);
        // }
        // else return;

        Console.WriteLine($"Hostname: {hostName} \n NewZone:{newZone} \n ZoneFilePath: {zoneFilePath} \n KeyAlgorithm: {keyAlgorithm}");

        foreach(var response in responses)
        {
            foreach (var record in response.Answers)
            {
                Console.WriteLine($"{record.RecordType} Record in {parentZone}: \n {record}");
            }
        }
        // foreach (var aRecord in result.Answers.ARecords())
        // {
        //     Console.WriteLine($"A Records:{aRecord}");
        // }    
    }
}


