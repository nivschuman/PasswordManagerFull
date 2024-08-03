import datetime


class Session:
    """
    A class to represent a user session

    Attributes:
        data (dict): A dictionary to store session data
        creation_date (datetime): The timestamp of when the session was created
    """

    def __init__(self):
        """
        Constructor:
            Initializes the session with an empty data dictionary and sets the creation date to the current time
        """

        self.data = dict()
        self.creation_date = datetime.datetime.now()

    def seconds_alive(self):
        """
        Calculates the number of seconds the session has been alive

        Returns:
            float: The total number of seconds the session has been alive
        """

        now_date = datetime.datetime.now()

        return (now_date - self.creation_date).total_seconds()
