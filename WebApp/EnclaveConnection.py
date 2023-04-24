import socket
import ssl
from typing import List
from qrcodegen import QrCode, QrSegment

sock : socket = None
ssock : ssl.SSLSocket = None

lastMessage : str = ""

def connectToEnclave():
    # SET VARIABLES
    print("Helllo!")
    packet, reply = "<packet>SOME_DATA</packet>", ""
    HOST, PORT = '127.0.0.1', 4433

    # PROTOCOL_TLS_CLIENT requires valid cert chain and hostname
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('cert.pem')

    global sock, ssock, lastMessage
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    ssock = context.wrap_socket(sock, server_hostname=HOST)
    # print(ssock.version())
    ssock.connect((HOST, PORT))
    # print("Test")
    lastMessage = receiveResponse()
    print(lastMessage)

def sendInput(text : str):
   ssock.sendall((text + "END").encode())
#    print(receiveResponse())

def receiveResponse() -> str:
    response : str = ""
    # ssock.recv(1200)

    while True:
        input = ssock.recv(1200).decode("utf-8")

        response += input
        if "END" in input:
            response = response[:-3]
            break

    global lastMessage
    lastMessage = response
    return response

def createQRCode(text : str) -> str:
    errcorlvl = QrCode.Ecc.LOW  # Error correction level
	
	# Make and print the QR Code symbol
    qr = QrCode.encode_text(text, errcorlvl)
    return qrToSVG(qr, 4)

def qrToSVG(qr: QrCode, border: int) -> str:
	"""Returns a string of SVG code for an image depicting the given QR Code, with the given number
	of border modules. The string always uses Unix newlines (\n), regardless of the platform."""
	if border < 0:
		raise ValueError("Border must be non-negative")
	parts: List[str] = []
	for y in range(qr.get_size()):
		for x in range(qr.get_size()):
			if qr.get_module(x, y):
				parts.append(f"M{x+border},{y+border}h1v1h-1z")
	return f"""<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 {qr.get_size()+border*2} {qr.get_size()+border*2}" stroke="none">
	<rect width="100%" height="100%" fill="#FFFFFF"/>
	<path d="{" ".join(parts)}" fill="#000000"/>
</svg>
"""
# 	return f"""<?xml version="1.0" encoding="UTF-8"?>
# <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
# <svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 {qr.get_size()+border*2} {qr.get_size()+border*2}" stroke="none">
# 	<rect width="100%" height="100%" fill="#FFFFFF"/>
# 	<path d="{" ".join(parts)}" fill="#000000"/>
# </svg>
# """