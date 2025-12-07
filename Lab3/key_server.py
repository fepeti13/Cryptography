import socket
import json

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 8080))
server_socket.listen()

public_key_map = {}

while True:
    client_socket, address = server_socket.accept()

    request = client_socket.recv(1024)
    if not request:
        response = json.dumps({"status": "error", "message": "Empty requst"})
        client_socket.sendall(response.encode('utf-8'))
        client_socket.close()
        continue

    request_string = request.decode('utf-8')
    try:
        request_data = json.loads(request_string)
    except Exception as e:
        response = json.dumps({"status": "error", "message": "Invalid json"})
        client_socket.sendall(response.encode('utf-8'))
        client_socket.close()
        continue

    if request_data["function"] == "register_public_key":
        print("[SERVER]: Got register request")
        public_key_map[request_data["params"]["id_client"]] = request_data["params"]["public_key"]

        response = json.dumps({"status": "success", "message": "Key registered"})
        client_socket.sendall(response.encode('utf-8'))
    elif request_data["function"] == "get_public_key":
        print("[SERVER]: Got get request")
        if request_data["params"]["id_client"] in public_key_map:
            response = json.dumps({"status": "success", "message": "Key delivered", "key": public_key_map[request_data["params"]["id_client"]]})
            client_socket.sendall(response.encode('utf-8'))
        else:
            response = json.dumps({"status": "error", "message": "Key not found"})
            client_socket.sendall(response.encode('utf-8'))

    else:
        print("[SERVER]: Got invalid request")
        response = json.dumps({"status": "error", "message": "Wrong request"})
        client_socket.sendall(response.encode('utf-8'))
    client_socket.close()