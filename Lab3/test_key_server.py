
import pytest
import socket
import json
import threading
import time





def send_request(host, port, data):
    """Helper function to send a request and get response"""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    
    
    client.sendall(json.dumps(data).encode('utf-8'))
    
    
    response = client.recv(1024)
    client.close()
    
    return json.loads(response.decode('utf-8'))


@pytest.fixture(scope="module")
def server():
    """Start the server in a separate thread before tests"""
    def run_server():
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("localhost", 8080))
        server_socket.listen()
        
        public_key_map = {}
        
        while True:
            client_socket, address = server_socket.accept()
            
            request = client_socket.recv(1024)
            if not request:
                response = json.dumps({"status": "error", "message": "Empty request"})
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
                    response = json.dumps({
                        "status": "success", 
                        "message": "Key delivered", 
                        "key": public_key_map[request_data["params"]["id_client"]]
                    })
                    client_socket.sendall(response.encode('utf-8'))
                else:
                    response = json.dumps({"status": "error", "message": "Key not found"})
                    client_socket.sendall(response.encode('utf-8'))
            else:
                print("[SERVER]: Got invalid request")
                response = json.dumps({"status": "error", "message": "Wrong request"})
                client_socket.sendall(response.encode('utf-8'))
            
            client_socket.close()
    
    
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    
    time.sleep(0.5)
    
    yield  
    
    


def test_register_public_key(server):
    """Test registering a public key"""
    request = {
        "function": "register_public_key",
        "params": {
            "id_client": "8001",
            "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
        }
    }
    
    response = send_request("localhost", 8080, request)
    
    assert response["status"] == "success"
    assert "registered" in response["message"].lower()


def test_get_existing_public_key(server):
    """Test getting a registered public key"""
    
    register_request = {
        "function": "register_public_key",
        "params": {
            "id_client": "8002",
            "public_key": "TEST_PUBLIC_KEY_123"
        }
    }
    send_request("localhost", 8080, register_request)
    
    
    get_request = {
        "function": "get_public_key",
        "params": {
            "id_client": "8002"
        }
    }
    
    response = send_request("localhost", 8080, get_request)
    
    assert response["status"] == "success"
    assert response["key"] == "TEST_PUBLIC_KEY_123"


def test_get_nonexistent_public_key(server):
    """Test getting a key that doesn't exist"""
    request = {
        "function": "get_public_key",
        "params": {
            "id_client": "99999"
        }
    }
    
    response = send_request("localhost", 8080, request)
    
    assert response["status"] == "error"
    assert "not found" in response["message"].lower()


def test_invalid_function(server):
    """Test sending an invalid function name"""
    request = {
        "function": "invalid_function",
        "params": {}
    }
    
    response = send_request("localhost", 8080, request)
    
    assert response["status"] == "error"


def test_update_existing_key(server):
    """Test that re-registering updates the key"""
    client_id = "8003"
    
    
    request1 = {
        "function": "register_public_key",
        "params": {
            "id_client": client_id,
            "public_key": "OLD_KEY"
        }
    }
    send_request("localhost", 8080, request1)
    
    
    request2 = {
        "function": "register_public_key",
        "params": {
            "id_client": client_id,
            "public_key": "NEW_KEY"
        }
    }
    send_request("localhost", 8080, request2)
    
    
    get_request = {
        "function": "get_public_key",
        "params": {
            "id_client": client_id
        }
    }
    response = send_request("localhost", 8080, get_request)
    
    assert response["key"] == "NEW_KEY"  


if __name__ == "__main__":
    pytest.main([__file__, "-v"])