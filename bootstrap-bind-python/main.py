# named-checkconf -l | grep -E ' (primary|secondary|master|slave|mirror)$' | awk '{print $1}'
import argparse
import sys

import dns.resolver
from dns.rdataclass import IN

parser = argparse.ArgumentParser()
parser.add_argument("--bind-config-file", type=str, help="Generate initial BIND configuration for signal zones")
parser.add_argument("zone_dir", type=str, help="Directory where the signal zone files are written")
args = parser.parse_args()

# Get zone names from stdin
zone_names = [dns.name.from_text(n.strip()) for n in sys.stdin if n.strip()]

signal_zones_nsset = dns.rrset.from_text("", 3600, IN, dns.rdatatype.NS, "ns1.example.org.", "ns2.example.nl.")

signal_zones = {}

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers.append("9.9.9.9")

for name in zone_names:
    print(f"Processing {name}")

    # Get CDS and CDNSKEY records
    answer_cds = resolver.resolve(name, dns.rdatatype.CDS, raise_on_no_answer=False)
    answer_cdnskey = resolver.resolve(name, dns.rdatatype.CDNSKEY, raise_on_no_answer=False)

    if not answer_cds and not answer_cdnskey:
        print(f"No CDS or CDNSKEY records for {name}")
        continue

    # Overwrite name in answer
    if answer_cds:
        answer_cds.rrset.name = dns.name.from_text(f"_dsboot.{name}") - dns.name.root
    if answer_cdnskey:
        answer_cdnskey.rrset.name = dns.name.from_text(f"_dsboot.{name}") - dns.name.root

    # Get NS set
    answer_ns = resolver.resolve(name, dns.rdatatype.NS, raise_on_no_answer=False)
    if not answer_ns:
        print(f"No answer to NS for {name}")
        continue

    # For nameserver for which we have a signaling zone, add CDS and CDNSKEY records
    for ns in answer_ns:
        if name.is_superdomain(ns.target):
            print(f"{ns} is in-bailiwick for {name}")
            continue

        ns_name = str(ns).rstrip(".")
        print(f"Checking {ns_name} for {name}")
        print(f"Adding records for {name} to {ns_name}")

        if ns_name not in signal_zones:
            signal_zones[ns_name] = dns.zone.Zone(origin=f'_signal.{ns_name}')
            with signal_zones[ns_name].writer() as writer:
                try:
                    answer_soa = resolver.resolve(dns.name.from_text(f"_dsboot.{name.to_text(omit_final_dot=True)}._signal.{ns_name}"), dns.rdatatype.SOA, raise_on_no_answer=False)
                    # Increase serial by 1
                    answer_soa.rrset[0].serial += 1
                    soa_rrset = answer_soa.rrset
                except dns.resolver.NXDOMAIN:
                    # Create SOA with serial 1
                    soa_rrset = dns.rrset.from_text("", 3600, IN, dns.rdatatype.SOA, "ex1.sidnlabs.nl. hostmaster.sidn.nl. 1 14400 3600 604800 300")
                writer.add(soa_rrset)
                writer.add(signal_zones_nsset)

        with signal_zones[ns_name].writer() as writer:
            if answer_cds:
                writer.add(answer_cds.rrset)
            if answer_cdnskey:
                writer.add(answer_cdnskey.rrset)

    if args.bind_config_file:
        with open(args.bind_config_file, "w") as config_file:
            for ns in signal_zones:
                zone_filename = f"{args.zone_dir.rstrip('/')}/{signal_zones[ns].origin.to_text(omit_final_dot=True)}.zone"
                config_file.write(f"zone \"{signal_zones[ns].origin.to_text(omit_final_dot=True)}\" {{ type master; file \"{zone_filename}\"; }};\n")

    for ns in signal_zones:
        zone_filename = f"{args.zone_dir.rstrip('/')}/{signal_zones[ns].origin.to_text(omit_final_dot=True)}.zone"
        signal_zones[ns].to_file(zone_filename, relativize=True, want_origin=True)