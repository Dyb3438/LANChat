import socket
from threading import Thread, Lock
import os

CONN_LIST = []
LOCK = Lock()

def getMyIP():
    local_hostname = socket.gethostname()
    ip = socket.gethostbyname_ex(local_hostname)[2]
    return ip[-1]

def logger_output(log, info=True):
    if info:
        print("\r[INFO] %s" % log, end="\n>>> ")
    else:
        print("\r%s" % log, end="\n>>> ")
    return

def server():
    global CONN_LIST, LOCK

    while True:
        try:
            conn, addr = s.accept()
            LOCK.acquire()
            CONN_LIST.append(conn)
            logger_output("Find a new connection at (%s:%d)" % (addr[0], addr[1]))
            LOCK.release()
        except (TimeoutError, socket.timeout):
            continue
    return

def receiver():
    global CONN_LIST, LOCK
    while True:
        remove_items = []
        for conn in CONN_LIST:
            remote_addr = conn.getpeername()
            try:
                message_length = conn.recv(2)
                if not message_length:
                    raise Exception("closed")
                message_length = int.from_bytes(message_length, byteorder='big', signed=False)
                message = conn.recv(message_length)
                if not message:
                    raise Exception("closed")
                logger_output('----------------------------------')
                logger_output('Receive from (%s:%d):' % (remote_addr[0], remote_addr[1]))
                logger_output(message.decode('utf-8'), False)
            except (TimeoutError, socket.timeout):
                continue
            except:
                logger_output('Exception raises on (%s:%d), which wil be removed from receiver list.' % (remote_addr[0], remote_addr[1]))
                remove_items.append(conn)

        if len(remove_items) > 0:
            LOCK.acquire()
            for item in remove_items:
                CONN_LIST.remove(item)
            LOCK.release()
    return

def sender():
    global CONN_LIST, LOCK
    while True:
        message = input(">>> ")
        if message in ["'''", '"""']:
            # multiples lines input
            message = b""
            while True:
                new_message = input("")
                if new_message in ["'''", '"""']:
                    break
                message += new_message.encode('utf-8')
                message += b'\n'
        elif message == "exit()":
            os._exit(1)
        else:
            message = message.encode('utf-8')
        message_len = len(message)
        for message_chunk_offset in range(0, message_len, 65535):
            message_chunk = message[message_chunk_offset: message_chunk_offset + 65535]
            remove_items = []
            for conn in CONN_LIST:
                try:
                    conn.send(len(message_chunk).to_bytes(2, byteorder='big', signed=False))
                    conn.send(message_chunk)
                except:
                    remove_items.append(conn)

            if len(remove_items) > 0:
                LOCK.acquire()
                for item in remove_items:
                    CONN_LIST.remove(item)
                LOCK.release()

        print("Send successfully.")
    return





if __name__ == "__main__":
    ip = input("Please input the remote ip [0.0.0.0 as the server end.]:")
    if ip.strip() == "":
        ip = "0.0.0.0"
    else:
        ip = ip.strip()

    port = input("Please input the remote port [2450]:")
    if port.strip() == "":
        port = 2450
    else:
        port = int(port.strip())
    
    threads = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        # , "127.0.0.1", getMyIP()
        if ip in ["0.0.0.0"]:
            s.bind((ip, port))
            s.listen(10)
            print("This is the listen end, listening on (%s:%d)." % (ip, port))
            t = Thread(target = server, args=())
            t.start()
            threads.append(t)
        else:
            s.connect((ip, port))
            CONN_LIST.append(s)
        
        t = Thread(target = receiver, args=())
        t.start()
        threads.append(t)

        t = Thread(target = sender, args=())
        t.start()
        threads.append(t)

        for t in threads:
            t.join()


