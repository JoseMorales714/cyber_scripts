import argparse
import socket


# sends and gets http req
def get_service_banner(ip, port):
    try:
        # AF_INET created ipv4 socket
        # SOCK_STREAM creates reliable stream socket for TCP commss
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # delay to ensure socket has been created properly and other ops
        sock.settimeout(3)
        sock.connect((ip, int(port)))

        # this is sending data
        # b for bytes that shows first part of HTTP request
        # \r\n is new line
        # encode converts IP address string to bytes using the utf=8
        # b"\r\n\r\n" is bytes literal represetting 2 consectuvie newline characters
        sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")

        # this will read 1024 bytes of data from packet
        # which is the max amount of data to be read at once
        banner = sock.recv(1024)
        sock.close()

        # this decodes banner from bytes to utf8 format
        return banner.decode('utf-8', errors='ignore')
    except Exception:
        print(Exception)
        return None


def main():
    
    # this fixes format of the CLI arguments
    parser = argparse.ArgumentParser(description='Service Banner Scanner')
    parser.add_argument('ip', help='IP address to scan')
    parser.add_argument('-p', '--ports', required=True, help='Ports to scan (comma-separated)')

    args = parser.parse_args()

    ip = args.ip
    
    # this adds all listed ports without the comma to ports
    ports = [port.strip() for port in args.ports.split(',')]

    print(f"Scanning IP: {ip}")
    for port in ports:
        print(f"Scanning port {port} on IP {ip}")
        banner = get_service_banner(ip, port)

        if banner:
            print(f"Service banner for port {port} on IP {ip}:\n{banner}\n")
        else:
            print(f"No service banner found for port {port} on IP: {ip}\n")


if __name__ == "__main__":
    main()
