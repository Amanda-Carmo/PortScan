import socket

hostname = socket.gethostname()
ip_address = socket.gethostbyname(hostname)

print(f"Seu endereço IP local é {ip_address}")
