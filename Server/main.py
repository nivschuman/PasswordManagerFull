from PasswordManager import PasswordManagerServer
from json import load


def main():
    config_file = open(r"dist/config.json")
    config_data = load(config_file)

    password_manager_server = PasswordManagerServer(config_data["host"], config_data["port"],
                                                    config_data["connection_string"], config_data["with_ssl"])
    password_manager_server.start_server()


if __name__ == '__main__':
    main()
