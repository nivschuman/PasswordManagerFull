import socket
import ssl
import re
import string
import time
from random import randint
from threading import Thread
from threading import Lock
from CommunicationProtocol import CommunicationProtocol, CommunicationProtocolException
from Session import Session


# TCP Socket Server which binds to host and port given
# Each client connection is handled in different thread
# Client connections go through different handler functions
# handler functions are called in added order. Result of one handler goes to the next.
class Server:
    """
    TCP Socket Server which binds to a given host and port.
    Each client connection is handled in a different thread.
    Client connections go through different handler functions.
    Handler functions are called in added order. The result of one handler goes to the next.

    Attributes:
        host (str): The host to bind the server to.
        port (int): The port to bind the server to.
        ssl_context (ssl.SSLContext): The SSL context for secure connections.
        server_socket (socket.socket): The server socket.
        handlers (list): List of handler functions to process client connections.
    """

    def __init__(self, host, port, with_ssl):
        """
        Constructor:
            Initializes the Server instance.

            Args:
                host (str): The host to bind the server to.
                port (int): The port to bind the server to.
                with_ssl (bool): Whether to use SSL for secure connections.
        """

        self.port = port
        self.host = host

        self.ssl_context = None
        if with_ssl:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(certfile=r"SSL/cert.pem", keyfile=r"SSL/key.pem")

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.handlers = []  # each handler is a function which takes client_socket, client_address, prev_result

    # add handler function to deal with client connection
    def add_handler(self, handler):
        """
        Adds a handler function to process client connections.

        Args:
            handler (function): The handler function to add.
        """

        self.handlers.append(handler)

    # remove handler function
    def remove_handler(self, handler):
        """
        Removes a handler function.

        Args:
            handler (function): The handler function to remove.
        """

        self.handlers.remove(handler)

    # receive message from client. Default receives 1024 bytes from client socket.
    def receive_message(self, client_socket, client_address):
        """
        Receives a message from the client. Default receives 1024 bytes from client socket.

        Args:
            client_socket (socket.socket): The client socket.
            client_address (tuple): The client address.

        Returns:
            bytes: The received message.
        """

        return client_socket.recv(1024)

    # what to do on client closing. Default just closes socket.
    def close_client(self, client_socket, client_address):
        """
        Handles client closing. Default just closes the socket.

        Args:
            client_socket (socket.socket): The client socket.
            client_address (tuple): The client address.
        """

        client_socket.close()

    # handle connection from client. message goes through all handler functions
    def handle_client(self, client_socket, client_address):
        """
        Handles connection from the client.
        The message is received using receive_message function.
        The message then goes through all handler functions.
        At the end close_client function is called.

        Args:
            client_socket (socket.socket): The client socket.
            client_address (tuple): The client address.
        """

        message = self.receive_message(client_socket, client_address)

        prev_result = message
        for handler in self.handlers:
            prev_result = handler(client_socket, client_address, prev_result)

        self.close_client(client_socket, client_address)

    # turn server on to forever serve
    def serve_forever(self):
        """
        Turns the server on to serve forever.
        """

        print(f"Starting Server on host={self.host}, port={self.port}")
        self.server_socket.bind((self.host, self.port))

        server_socket = self.server_socket
        if self.ssl_context is not None:
            server_socket = self.ssl_context.wrap_socket(server_socket, server_side=True)

        while True:
            server_socket.listen()
            client_socket, client_address = server_socket.accept()
            print(f"Received Connection from {client_address}")
            client_thread = Thread(target=self.handle_client, args=(client_socket, client_address))
            client_thread.start()


# Server with Storing Session capabilities
# todo is session cleanup thread safe?!
class SessionServer(Server):
    """
    Server with storing session capabilities.

    Attributes:
        sessions (dict): Dictionary storing sessions with session tokens as keys and session objects as values.
        session_token_length (int): Length of the session token.
        session_ttl (int): Time-to-live for a session in seconds.
        session_cleanup_thread (threading.Thread): Thread to remove expired sessions.
    """

    def __init__(self, host, port, session_token_length, session_ttl, with_ssl):
        """
        Constructor:
             Initializes the SessionServer instance.

             Args:
                 host (str): The host to bind the server to.
                 port (int): The port to bind the server to.
                 session_token_length (int): Length of the session token.
                 session_ttl (int): Time-to-live for a session in seconds.
                 with_ssl (bool): Whether to use SSL for secure connections.
        """

        super().__init__(host, port, with_ssl)

        self.sessions = dict()  # key is session token, value is session object
        self.session_token_length = session_token_length

        self.session_ttl = session_ttl  # number of seconds that session is allowed to live
        self.session_cleanup_thread = Thread(target=self.remove_sessions)

    def serve_forever(self):
        """
        Turns the server on to serve forever and starts the session cleanup thread.
        """

        self.session_cleanup_thread.start()
        super().serve_forever()

    # generate unique token for new session
    def generate_session_token(self, length):
        """
        Generates a unique token for a new session.

        Args:
            length (int): Length of the session token.

        Returns:
            str: The generated session token.
        """

        characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
        token = ""

        while token in self.sessions or token == "":
            token = ""
            for i in range(length):
                token += characters[randint(0, len(characters)-1)]

        return token

    # create a session and return its token
    def create_session(self):
        """
         Creates a session and returns its token.

         Returns:
             str: The session token.
         """

        token = self.generate_session_token(self.session_token_length)
        self.sessions[token] = Session()

        return token

    # get session associated with token
    def get_session(self, token):
        """
        Gets the session associated with the token.

        Args:
            token (str): The session token.

        Returns:
            Session: The session object.
        """

        return self.sessions.get(token)

    # close session with token
    def close_session(self, token):
        """
        Closes the session with the specified token.

        Args:
            token (str): The session token.
        """

        self.sessions.pop(token)

    # removal for sessions that have expired
    def remove_sessions(self):
        """
        Removes sessions that have expired.
        Runs on the session cleanup thread.
        """

        while True:
            remove_tokens = []

            try:
                # find sessions that have expired
                for token, session in self.sessions.items():
                    if session.seconds_alive() > self.session_ttl:
                        remove_tokens.append(token)
            except RuntimeError as e:  # dictionary changed size during iteration
                return

            # remove expired sessions from dictionary
            for token in remove_tokens:
                print(f"Deleted session with token={token}")
                self.sessions.pop(token)

            time.sleep(5)


# Server which works with the Communication Protocol
class CommunicationProtocolServer(SessionServer):
    """
    Server which works with the Communication Protocol.

    Attributes:
        method_handlers (dict): Dictionary with method names as keys and functions to handle methods as values.
    """

    def __init__(self, host, port, session_ttl, with_ssl):
        """
        Constructor:
             Initializes the CommunicationProtocolServer instance.

             Args:
                 host (str): The host to bind the server to.
                 port (int): The port to bind the server to.
                 session_ttl (int): Time-to-live for a session in seconds.
                 with_ssl (bool): Whether to use SSL for secure connections.
         """

        super().__init__(host, port, 8, session_ttl, with_ssl)

        self.handlers.append(self.parse_message)
        self.handlers.append(self.session_generator)
        self.handlers.append(self.method_handler)

        self.method_handlers = dict()  # key is method name, value is function to handle method

    # if request with Method=method is received, method_function will be called
    # method_function gets req, res and session object relevant to req session token
    # res is changed in method_function
    def handle_method(self, method, method_function):
        """
        Adds the method_function to the method_handlers dictionary, with method as the key.
        If a request with Method=method is received, method_function will be called.

         Args:
             method (str): The method name.
             method_function (function): The function to handle the method.
         """

        self.method_handlers[method] = method_function

    def receive_message(self, client_socket, client_address):
        """
         Receives a full communication protocol byte message from the client.
         The receiving is done using the header_length and the content length.
         Returns the fully received communication protocol byte message for the parse message handler.

         Args:
             client_socket (socket.socket): The client socket.
             client_address (tuple): The client address.

         Returns:
             bytes: The complete communication protocol byte message.

         Raises:
             CommunicationProtocolException: If the message does not start with 'req' or 'res'.
         """

        req_res = client_socket.recv(3)

        if req_res != "req".encode() and req_res != "res".encode():
            data = client_socket.recv(1)
            while data != "":
                req_res += data
                data = client_socket.recv(1)
            raise CommunicationProtocolException(req_res, "Message does not start with res or req")

        # receive headers
        header_length_bytes = client_socket.recv(6)[1:5]
        header_length = int.from_bytes(header_length_bytes, "little")
        headers = client_socket.recv(header_length-9)

        # get Content-Length header to find length of body
        headers_list = headers.decode()
        headers_list = headers_list.split(":")
        headers_list.pop(-1)
        regular_expression = re.compile(r"Content-Length=[0-9]+")
        content_length_header = list(filter(regular_expression.match, headers_list))[0]
        content_length = content_length_header.split("=")[1]
        content_length = int(content_length)

        # receive body
        body = client_socket.recv(content_length)

        # return complete byte message
        return req_res + ":".encode() + header_length_bytes + ":".encode() + headers + body

    # turn byte message into CommunicationProtocol object for next handler
    def parse_message(self, client_socket, client_address, message):
        """
        Turns full communication protocol byte message into CommunicationProtocol object for the next handler.

        Args:
            client_socket (socket.socket): The client socket.
            client_address (tuple): The client address.
            message (bytes): The byte message.

        Returns:
            CommunicationProtocol: The parsed communication protocol message.
        """

        return CommunicationProtocol.from_bytes(message)

    def session_generator(self, client_socket, client_address, req):
        session_value = req.get_header_value("Session")

        # create new session for use with client
        if session_value == "*":
            session_token = self.create_session()
            req.set_header_value("Session", session_token)

        return req

    # creates response to specific method and sends it to client
    def method_handler(self, client_socket, client_address, req):
        """
        Calls specific method handler function based on client requested method.
        Method is called with req object, new res object and session object.
        Res object is filled up by method handler function and is then sent to client.

        Args:
            client_socket (socket.socket): The client socket.
            client_address (tuple): The client address.
            req (CommunicationProtocol): The request message.

        Returns:
            tuple: The request and response messages for possible extra handling.
        """

        # response object. Changed in method handler.
        res = CommunicationProtocol("res", dict(), None)

        # get session object using req session token
        session = None
        session_token = req.get_header_value("Session")
        if session_token[0] == "~":
            session_token = session_token[1:]
        if session_token != "-":
            session = self.get_session(session_token)

        # set session token in response
        res.set_header_value("Session", session_token)

        # call handler to method
        method = req.get_header_value("Method")
        self.method_handlers[method](req, res, session)

        # send response to client
        client_socket.send(res.to_bytes())

        # close session if requested to
        if req.get_header_value("Session")[0] == "~":
            self.close_session(session_token)

        # return req and res for possible extra handles
        return req, res
