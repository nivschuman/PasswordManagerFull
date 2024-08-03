from Server import CommunicationProtocolServer
import pyodbc
import json
import base64
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from random import randbytes


class PasswordManagerServer:
    """
    A server for managing user passwords with various functionalities such as user creation, login,
    retrieving and setting passwords, and deleting users.

    Attributes:
        server (CommunicationProtocolServer): The communication protocol server instance.
        db_connection (pyodbc.Connection): The database connection.
    """

    def __init__(self, host, port, db_connection_string, with_ssl):
        """
        Constructor:
            Initializes the PasswordManagerServer with the specified parameters.

            Args:
                host (str): The host address.
                port (int): The port number.
                db_connection_string (str): The database connection string.
                with_ssl (bool): Whether to use SSL.
        """

        self.server = CommunicationProtocolServer(host, port, 10800, with_ssl)  # session ttl is 3 hours
        self.db_connection = pyodbc.connect(db_connection_string)

        self.server.handle_method("create_user", self.create_user)
        self.server.handle_method("login_request", self.login_request)
        self.server.handle_method("login_test", self.login_test)
        self.server.handle_method("get_sources", self.get_sources)
        self.server.handle_method("get_password", self.get_password)
        self.server.handle_method("set_password", self.set_password)
        self.server.handle_method("delete_password", self.delete_password)
        self.server.handle_method("delete_user", self.delete_user)

    def start_server(self):
        """
        Starts the server to listen for incoming requests.
        """

        self.server.serve_forever()

    # receive json with publicKey, userName and create such user
    # returns ascii with info on success or error
    def create_user(self, req, res, session):
        """
        Creates a new user with the provided public key and username.

        Args:
            req (CommunicationProtocol): The request message.
            res (CommunicationProtocol): The response message.
            session (Session): The current session.

        The request body should contain a JSON object with the following keys:
            - publicKey (str): The user's public key, encoded in base64.
            - userName (str): The username.

        The response body will contain an ASCII string indicating success or error.
        """

        db_cursor = self.db_connection.cursor()

        body_str = req.body.decode("ascii")
        body_json = json.loads(body_str)

        public_key_bytes = base64.b64decode(body_json["publicKey"])
        user_name = body_json["userName"]

        try:
            # check if there already exists a user with given username
            public_key_str = f"0x{public_key_bytes.hex()}"
            db_cursor.execute(f"SELECT UserName, PublicKey FROM Users WHERE UserName=?", user_name)
            user_with_same_username = len(db_cursor.fetchall()) != 0
            db_cursor.execute(f"SELECT UserName, PublicKey FROM Users WHERE PublicKey=?", public_key_str)
            user_with_same_public_key = len(db_cursor.fetchall()) != 0

            if user_with_same_username:
                res.body = "User with this username already exists, choose a different username".encode("ascii")
            elif user_with_same_public_key:
                res.body = "User with this public key already exists, choose a different public key".encode("ascii")
            else:
                db_cursor.execute(f"INSERT INTO Users (UserName, PublicKey) VALUES (?, CONVERT(VARBINARY(300),?,1))", user_name, public_key_str)
                db_cursor.commit()
                res.body = "Success".encode("ascii")

            res.set_header_value("Content-Length", len(res.body))
            res.set_header_value("Method", "create_user")
            res.set_header_value("Content-Type", "ascii")
        except pyodbc.Error as db_error:
            print(db_error)
            sql_state = db_error.args[0]
            sql_error_message = db_error.args[1]
            res.body = f"Failed - server database error\nSQL STATE: {sql_state}\nError message: {sql_error_message}"
            res.set_header_value("Content-Length", len(res.body))
            res.set_header_value("Method", "create_user")
            res.set_header_value("Content-Type", "ascii")

    # receive username in ascii and return encrypted random 64 bits, no body is returned on error
    def login_request(self, req, res, session):
        """
        Handles a login request by returning an encrypted random 64-bit number.

        Args:
            req (CommunicationProtocol): The request message.
            res (CommunicationProtocol): The response message.
            session (Session): The current session.

        The request body should contain the username as an ASCII string.

        The response body will contain the encrypted random 64-bit number, or no body if there is an error.
        """

        db_cursor = self.db_connection.cursor()

        user_name = req.body.decode("ascii")

        # get user's public key from database
        public_key_bytes = None
        try:
            db_cursor.execute(f"SELECT PublicKey FROM Users WHERE UserName=?", user_name)
            public_key_bytes = db_cursor.fetchall()
        except pyodbc.Error as db_error:
            print(db_error)
            res.body = None
            res.set_header_value("Content-Length", 0)
            res.set_header_value("Method", "login_request")
            res.set_header_value("Content-Type", "bytes")
            return

        # user does not exists or this was called without a session
        if len(public_key_bytes) == 0 or session is None:
            res.body = None
            res.set_header_value("Content-Length", 0)
        else:
            public_key_bytes = public_key_bytes[0][0]
            rsa_key = RSA.importKey(public_key_bytes)
            cipher = PKCS1_v1_5.new(rsa_key)

            # generate random 64 bit number and encrypt it
            random_number = randbytes(8)
            random_number_encrypted = cipher.encrypt(random_number)

            # return number in body
            res.body = random_number_encrypted
            res.set_header_value("Content-Length", len(res.body))

            # store number in session and user name
            session.data["loginNumber"] = random_number
            session.data["loginUserName"] = user_name

        res.set_header_value("Method", "login_request")
        res.set_header_value("Content-Type", "bytes")

    # receive decrypted 64 bits and if they match bits in session store logged in uid
    # returns ascii with info for success or failure
    def login_test(self, req, res, session):
        """
        Tests the login by verifying the decrypted 64-bit number.

        Args:
            req (CommunicationProtocol): The request message.
            res (CommunicationProtocol): The response message.
            session (Session): The current session.

        The request body should contain the decrypted 64-bit number as bytes.

        The response body will contain an ASCII string indicating success or failure.
        """

        db_cursor = self.db_connection.cursor()

        decrypted_number_bytes = req.body

        if session is None:
            res.body = "Failed - no session".encode("ascii")
        elif session.data.get("loginNumber") is None:
            res.body = "Failed - no login number in session".encode("ascii")
        elif session.data.get("loginUserName") is None:
            res.body = "Failed - no login username in session".encode("ascii")
        elif decrypted_number_bytes != session.data["loginNumber"]:
            res.body = "Failed - incorrect number".encode("ascii")
        else:  # correct number and data is in session
            try:
                # get user id from database
                user_name = session.data["loginUserName"]
                db_cursor.execute(f"SELECT ID FROM Users WHERE UserName=?", user_name)
                user_id = db_cursor.fetchall()

                if len(user_id) == 0:
                    res.body = f"Failed - user {user_name} doesn't exist".encode("ascii")
                else:
                    session.data["loggedInUID"] = user_id[0][0]
                    res.body = "Success".encode("ascii")
            except pyodbc.Error as db_error:
                print(db_error)
                sql_state = db_error.args[0]
                sql_error_message = db_error.args[1]
                res.body = f"Failed - server database error\nSQL STATE: {sql_state}\nError message: {sql_error_message}"

        res.set_header_value("Content-Length", len(res.body))
        res.set_header_value("Method", "login_test")
        res.set_header_value("Content-Type", "ascii")

    # returns json array of all sources tied to user in session. Return no body if error
    def get_sources(self, req, res, session):
        """
        Retrieves the sources tied to the logged-in user.

        Args:
            req (CommunicationProtocol): The request message.
            res (CommunicationProtocol): The response message.
            session (Session): The current session.

        The response body will contain a JSON array of sources, or no body if there is an error.
        """

        db_cursor = self.db_connection.cursor()

        # no session
        if session is None:
            res.body = None
            res.set_header_value("Content-Length", 0)
            res.set_header_value("Method", "get_sources")

        # user is not logged in
        if session.data.get("loggedInUID") is None:
            res.body = None
            res.set_header_value("Content-Length", 0)
            res.set_header_value("Method", "get_sources")
            return

        user_id = session.data["loggedInUID"]

        # get sources
        sources_db = None
        sources = []
        try:
            db_cursor.execute(f"SELECT Source FROM Passwords WHERE UserID=?", user_id)
            sources_db = db_cursor.fetchall()
        except pyodbc.Error as db_error:
            print(db_error)
            res.body = None
            res.set_header_value("Content-Length", 0)
            res.set_header_value("Method", "get_sources")
            return

        for source_item in sources_db:
            sources.append(source_item[0])

        sources_json = json.dumps(sources)
        sources_json = sources_json.encode("ascii")

        res.body = sources_json
        res.set_header_value("Content-Length", len(res.body))
        res.set_header_value("Method", "get_sources")
        res.set_header_value("Content-Type", "ascii json")

    # gets ascii string of password source and returns encrypted password, no body if error
    def get_password(self, req, res, session):
        """
         Retrieves the password for the specified source for the logged in user.

         Args:
             req (CommunicationProtocol): The request message.
             res (CommunicationProtocol): The response message.
             session (Session): The current session.

         The request body should contain the source as an ASCII string.

         The response body will contain the encrypted password, or no body if there is an error.
         """

        db_cursor = self.db_connection.cursor()

        source = req.body.decode("ascii")

        # no session
        if session is None:
            res.body = None
            res.set_header_value("Content-Length", 0)
            res.set_header_value("Method", "get_password")
            return

        # user is not logged in
        if session.data.get("loggedInUID") is None:
            res.body = None
            res.set_header_value("Content-Length", 0)
            res.set_header_value("Method", "get_password")
            return

        user_id = session.data["loggedInUID"]

        password = None
        try:
            db_cursor.execute(f"SELECT Password FROM Passwords WHERE UserID=? AND Source=?", user_id, source)
            password = db_cursor.fetchall()
        except pyodbc.Error as db_error:
            print(db_error)
            res.body = None
            res.set_header_value("Content-Length", 0)
            res.set_header_value("Method", "get_password")
            return

        # no password found
        if len(password) == 0:
            res.body = None
            res.set_header_value("Content-Length", 0)
            res.set_header_value("Method", "get_password")
            return

        password = password[0][0]

        res.body = password
        res.set_header_value("Content-Length", len(res.body))
        res.set_header_value("Method", "get_password")
        res.set_header_value("Content-Type", "bytes")

    # gets json of source and password encoded in base64, returns ascii if success or failure
    def set_password(self, req, res, session):
        """
        Sets the password for a specific source for the logged in user.

        Args:
            req (CommunicationProtocol): The request message.
            res (CommunicationProtocol): The response message.
            session (Session): The current session.

        The request body should contain a JSON object with the following keys:
            - source (str): The source.
            - password (str): The password.

        The response body will contain an ASCII string indicating success or failure.
        """

        db_cursor = self.db_connection.cursor()

        body_str = req.body.decode("ascii")
        body_json = json.loads(body_str)

        source = body_json["source"]
        password = base64.b64decode(body_json["password"])
        password_str = f"0x{password.hex()}"

        # no session
        if session is None:
            res.body = "Failed - no session".encode("ascii")
            res.set_header_value("Content-Length", len(res.body))
            res.set_header_value("Method", "set_password")
            res.set_header_value("Content-Type", "ascii")
            return

        # user is not logged in
        if session.data.get("loggedInUID") is None:
            res.body = "Failed - not logged in".encode("ascii")
            res.set_header_value("Content-Length", len(res.body))
            res.set_header_value("Method", "set_password")
            res.set_header_value("Content-Type", "ascii")
            return

        user_id = session.data["loggedInUID"]

        # password for source already exists
        password = None
        try:
            db_cursor.execute(f"SELECT Password FROM Passwords WHERE Source=? AND UserID=?", source, user_id)
            password = db_cursor.fetchall()
        except pyodbc.Error as db_error:
            print(db_error)
            sql_state = db_error.args[0]
            sql_error_message = db_error.args[1]
            res.body = f"Failed - server database error\nSQL STATE: {sql_state}\nError message: {sql_error_message}"
            res.set_header_value("Content-Length", len(res.body))
            res.set_header_value("Method", "set_password")
            res.set_header_value("Content-Type", "ascii")
            return

        if len(password) != 0:
            res.body = "Failed - password for source already exists".encode("ascii")
            res.set_header_value("Content-Length", len(res.body))
            res.set_header_value("Method", "set_password")
            res.set_header_value("Content-Type", "ascii")
            return

        # enter into database
        try:
            db_cursor.execute(f"INSERT INTO Passwords (Source, Password, UserID) VALUES (?, CONVERT(BINARY(256),?,1), ?)", source, password_str, user_id)
            db_cursor.commit()
            res.body = "Success".encode("ascii")
        except pyodbc.Error as db_error:
            print(db_error)
            sql_state = db_error.args[0]
            sql_error_message = db_error.args[1]
            res.body = f"Failed - server database error\nSQL STATE: {sql_state}\nError message: {sql_error_message}"

        res.set_header_value("Content-Length", len(res.body))
        res.set_header_value("Method", "set_password")
        res.set_header_value("Content-Type", "ascii")

    # gets source and deletes password record with given source. Returns ascii for success or failure
    def delete_password(self, req, res, session):
        """
        Deletes the password for a specific source for the logged in user.

        Args:
            req (CommunicationProtocol): The request message.
            res (CommunicationProtocol): The response message.
            session (Session): The current session.

        The request body should contain the source as an ASCII string.

        The response body will contain an ASCII string indicating success or failure.
        """

        db_cursor = self.db_connection.cursor()

        source = req.body.decode("ascii")

        # no session
        if session is None:
            res.body = "Failed - no session".encode("ascii")
            res.set_header_value("Content-Length", len(res.body))
            res.set_header_value("Method", "delete_password")
            res.set_header_value("Content-Type", "ascii")
            return

        # user is not logged in
        if session.data.get("loggedInUID") is None:
            res.body = "Failed - not logged in".encode("ascii")
            res.set_header_value("Content-Length", len(res.body))
            res.set_header_value("Method", "delete_password")
            res.set_header_value("Content-Type", "ascii")
            return

        user_id = session.data["loggedInUID"]

        # password for source doesn't exists
        password = None
        try:
            db_cursor.execute(f"SELECT Password FROM Passwords WHERE Source=? AND UserID=?", source, user_id)
            password = db_cursor.fetchall()
        except pyodbc.Error as db_error:
            print(db_error)
            sql_state = db_error.args[0]
            sql_error_message = db_error.args[1]
            res.body = f"Failed - server database error\nSQL STATE: {sql_state}\nError message: {sql_error_message}"
            res.set_header_value("Content-Length", len(res.body))
            res.set_header_value("Method", "delete_password")
            res.set_header_value("Content-Type", "ascii")
            return

        if len(password) == 0:
            res.body = "Failed - password for source doesn't exist".encode("ascii")
            res.set_header_value("Content-Length", len(res.body))
            res.set_header_value("Method", "delete_password")
            res.set_header_value("Content-Type", "ascii")
            return

        # delete password record from database
        try:
            db_cursor.execute(f"DELETE FROM Passwords WHERE Source=? AND UserID=?", source, user_id)
            db_cursor.commit()
            res.body = "Success".encode("ascii")
        except pyodbc.Error as db_error:
            print(db_error)
            sql_state = db_error.args[0]
            sql_error_message = db_error.args[1]
            res.body = f"Failed - server database error\nSQL STATE: {sql_state}\nError message: {sql_error_message}"

        res.set_header_value("Content-Length", len(res.body))
        res.set_header_value("Method", "delete_password")
        res.set_header_value("Content-Type", "ascii")

    # receives nothing, deletes all user records of logged in user. Returns ascii on success or failure
    def delete_user(self, req, res, session):
        """
        Deletes the currently logged-in user.

        Args:
            req (CommunicationProtocol): The request message.
            res (CommunicationProtocol): The response message.
            session (Session): The current session.

        The response body will contain an ASCII string indicating success or failure.
        """

        db_cursor = self.db_connection.cursor()

        # no session
        if session is None:
            res.body = "Failed - no session".encode("ascii")
            res.set_header_value("Content-Length", len(res.body))
            res.set_header_value("Method", "delete_user")
            res.set_header_value("Content-Type", "ascii")
            return

        # user is not logged in
        if session.data.get("loggedInUID") is None:
            res.body = "Failed - not logged in".encode("ascii")
            res.set_header_value("Content-Length", len(res.body))
            res.set_header_value("Method", "delete_user")
            res.set_header_value("Content-Type", "ascii")
            return

        user_id = session.data["loggedInUID"]

        try:
            # delete all password records tied to user id
            db_cursor.execute(f"DELETE FROM Passwords WHERE UserID=?", user_id)

            # delete user record tied to user id
            db_cursor.execute(f"DELETE FROM Users WHERE ID=?", user_id)

            # commit execution
            db_cursor.commit()

            res.body = "Success".encode("ascii")
        except pyodbc.Error as db_error:
            db_cursor.rollback()

            print(db_error)
            sql_state = db_error.args[0]
            sql_error_message = db_error.args[1]
            res.body = f"Failed - server database error\nSQL STATE: {sql_state}\nError message: {sql_error_message}"

        res.set_header_value("Content-Length", len(res.body))
        res.set_header_value("Method", "delete_user")
        res.set_header_value("Content-Type", "ascii")
