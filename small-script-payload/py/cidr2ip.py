# cidr_to_ips.py

import ipaddress

def cidr_to_ips(input_file, output_file):
    """
    Convert CIDR ranges in the input file to individual IP addresses and save them to the output file.

    Args:
        input_file (str): Path to the file containing CIDR ranges, one per line.
        output_file (str): Path to the file where individual IP addresses will be saved.

    Returns:
        None
    """
    try:
        with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
            for line in infile:
                cidr = line.strip()
                try:
                    # Generate all IPs in the CIDR block
                    network = ipaddress.ip_network(cidr, strict=False)
                    for ip in network:
                        outfile.write(str(ip) + '\n')
                except ValueError:
                    print(f"Invalid CIDR: {cidr}")
                    continue

        print(f"IP addresses have been written to {output_file}")

    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Convert CIDR ranges to IP addresses")
    parser.add_argument("input_file", help="File containing CIDR ranges")
    parser.add_argument("output_file", help="File to save individual IP addresses")
    args = parser.parse_args()

    cidr_to_ips(args.input_file, args.output_file)

