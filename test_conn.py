import socket
import ssl

def test_conn():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        conn = context.wrap_socket(s, server_hostname='127.0.0.1')
        conn.connect(('127.0.0.1', 8081))
        print("Connected to 8081 successfully")
        conn.close()
    except Exception as e:
        print(f"Failed to connect to 8081: {e}")

if __name__ == "__main__":
    test_conn()
