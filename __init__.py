__author__ = 'Robert Roy'

import hashlib
import os
import tkinter


class CommandInterpreter:
    def __init__(self, output_function):
        if not hasattr(output_function, "__call__"):
            raise ValueError("An attempt has been made to pass a non-callable value as command_function")
        self.output_function = output_function
        self.commands = [[], [], []]
        self.add_command("HELP", self.describe_functions, "Provides a list of all valid functions.")

    def add_command(self, command_text, command_function, command_description):
        if not isinstance(command_text, str):
            raise ValueError("An attempt has been made to pass a non-string value as command_text")
        if not hasattr(command_function, "__call__"):
            raise ValueError("An attempt has been made to pass a non-callable value as command_function")
        if not isinstance(command_description, str):
            raise ValueError("An attempt has been made to pass a non-string value as command_description")
        self.commands[0].append(command_text.upper())
        self.commands[1].append(command_function)
        self.commands[2].append(command_description)

    def delete_command(self, command_text):
        for counter in range(0, len(self.commands[0])):
            if command_text == self.commands[0][counter]:
                self.commands[0].pop(counter)

    def describe_functions(self):
        description = "Available Commands:\n"
        for counter in range(0, len(self.commands[0])):
            # noinspection PyTypeChecker
            description += "• " + self.commands[0][counter] + "\n - " + self.commands[2][counter] + "\n"
        self.output_function(description)

    def run_command(self, potential_command):
        # TODO Add the capacity to pass parameters to functions using inspect.getargspec
        separated_command = self.split_by_string(potential_command, " ")
        if potential_command in self.commands[0]:
            run_index = self.commands[0].index(potential_command)
            # noinspection PyCallingNonCallable
            return self.commands[1][run_index]()
        else:
            return self.output_function("The attempted command is invalid. Please try again.")

    @staticmethod
    def split_by_string(split_this_string, split_at_this_string):
        split_string_as_list = []
        if split_at_this_string in split_this_string:
            split_string_as_list = split_this_string.split(split_at_this_string)
        else:
            split_string_as_list.append(split_this_string)
        return split_string_as_list

    def debugger(self, output_function, verbose):
        return ""
        # TODO Code this


class ReusableTextParser:
    def __init__(self, raw_data, raw_key, encryption_strength):
        # raw_data = string
        # raw_key = string
        # encryption_strength = integer
        # notes:
        # it is advised to delete the key submitted to the creation of the class to reduce the key's time in RAM
        # suggested encryption_strength is anywhere between 50 and 900, higher levels may cause performance issues
        self.iterations = encryption_strength
        self.key = self.get_sha1_hash(raw_key)
        self.data = self.convert_string_to_int_array(raw_data)

    def set_key(self, raw_key):
        # raw_key = string
        # sets self.key = SHA1 hashed raw_key
        self.key = self.get_sha1_hash(raw_key)

    def set_data(self, raw_data):
        # raw_data = string
        # converts raw_data from a string into an array of integer values equal to ascii equivalents
        self.data = self.convert_string_to_int_array(raw_data)

    def __set_sample_data(self):
        # creates a sample set of data for self
        self.set_key("SampleKey")
        self.set_data("SampleData")

    def get_string(self):
        # returns self.data converted to a string
        return self.convert_ascii_array_to_string(self.data)

    def encode(self):
        # encodes data according to self values
        self.data = self.__encode_decode(self.key, self.data, self.iterations, True)

    def decode(self):
        # decodes data according to self values
        self.data = self.__encode_decode(self.key, self.data, self.iterations, False)

    @staticmethod
    def convert_string_to_int_array(string_to_convert):
        # strings_to_convert = string
        # converts strings to an array of ASCII values
        # returns integer[]
        int_array = []
        for counter in range(0, len(string_to_convert)):
                int_array.append(ord(string_to_convert[counter]))
        return int_array

    @staticmethod
    def convert_ascii_array_to_string(ascii_integer_array):
        # ascii_integer_array = integer[]
        # converts integer array of ASCII values to string
        # returns string
        converted_string = ""
        for counter in range(0, len(ascii_integer_array)):
            if ascii_integer_array[counter] < 0:
                raise ValueError("An attempt was made to convert a negative integer value to an ASCII character. See "
                                 "following array: " + str(ascii_integer_array))
            else:
                converted_string += chr(ascii_integer_array[counter])
        return converted_string

    @staticmethod
    def get_sha1_hash(hash_this_string):
        # hash_this_string = string
        # Gets the hash of parameter string using SHA1
        # returns string
        return hashlib.sha1(hash_this_string.encode()).hexdigest()

    def __encode_decode(self, encoding_key, encode_this, iterations, add):
        # encoding_key = string : anything will do
        # encode_this = integer[] : this is any array of ASCII characters
        # iterations = integer : will define how many times the program recursively calls itself
        # add = boolean : true begins the alternation of add & subtracting ascii values by adding first run through then
        #   subtracting for the next recursive instance
        alternator = -1
        if add:
            alternator = 1
        encoded_output = []
        for counter in range(0, len(encode_this)):
            encoding_key_index = counter % len(encoding_key)  # to avoid going past maximum index of encoding key
            encoded_output.append(encode_this[counter] + ord(encoding_key[encoding_key_index]) * alternator)
        if iterations == 1:
            return encoded_output
        else:
            encoding_key = self.get_sha1_hash(encoding_key)
            return self.__encode_decode(
                encoding_key, encoded_output, iterations - 1, not add)

    def debug(self, verbose):
        # Debugs the program by calling all of its functions and comparing strings & self.data
        # verbose will cause the program to output a little bit more data, such as self.data & self.data
        #   converted to a string
        print("Debugging \"ReusableTextParser\":")
        print("Clearing data and setting sample data...")
        self.__set_sample_data()
        print("Success! Confirming sample Char value array is created...")
        integer_check_1 = self.data
        if verbose:
            print("Success! Now printing Char value Array...")
            print(integer_check_1)
        print("Success! Now converting Char value array to string...")
        string_check_1 = ""
        string_check_1 += self.get_string()
        if verbose:
            print("Success! Now printing string...")
            print(string_check_1)
        print("Success! Now encoding ASCII array using key...")
        self.encode()
        print("Success! Now comparing ASCII arrays...")
        integer_check_2 = self.data
        if integer_check_1 == integer_check_2:
            print("Failure: Converted array is identical to original array")
            exit()
        if verbose:
            print("Success! Now printing new integer array...")
            print(integer_check_2)
        print("Success! Now decoding back to original using key...")
        self.decode()
        print("Success! Now comparing to original array...")
        integer_check_3 = self.data
        if integer_check_1 != integer_check_3:
            print("Failure: Decoded array does not match original array")
            exit()
        print("Success! Text parser fully functioning!")


class File:
    def __init__(self, file_path):
        # Simple class created to make file creation reading/writing easier.
        # file_path is a string, should be in the form "c:/folder/file.extension"
        # exists indicates whether or not the file already exists
        # isopen indicates whether or not the program already has the desired file open
        # self.file becomes "open(self.path, [read/write])" and is not used as a string
        # Example initialization:
        # new_file = File(os.path.join(File.user_documents_folder(), "Program_Name", "Program_Data.txt"))
        self.exists = False
        self.isopen = False
        self.path = file_path
        self.file = ""
        if os.path.isfile(self.path):
            self.exists = True

    def create(self):
        # Creates a file at self.path is such a thing is possible
        # Will create as much or as little as is necessary to make the file, automatically
        # detecting whether or not directories must be created
        if os.path.isfile(self.path):
            self.file = open(self.path, "w+")
            self.file.close()
        elif os.path.isdir(os.path.dirname(self.path)):
            self.file = open(self.path, "w+")
            self.file.close()
        else:
            os.makedirs(os.path.dirname(self.path))
            self.file = open(self.path, "w+")
            self.file.close()
        self.exists = True

    def open(self):
        # Opens up a file for editing. This will lock the file and prevent it from being edited by other programs
        if not self.isopen:
            if self.exists:
                self.file = open(self.path, "r+")
                self.isopen = True
            else:
                raise ValueError("An attempt has been made to open a file that does not exist.")
        else:
            raise ValueError("An attempt to open an opened file has been made.")

    def close(self):
        # Closes a file and allows it to be used by other applications.
        if self.isopen:
            self.isopen = False
            self.file.close()
        else:
            raise ValueError("An attempt to close a closed file has been made.")

    def write_all(self, text):
        # text = string
        # This will erase everything in a file and write a string to it
        if self.isopen:
            self.file.truncate()
            self.file.write(text)
        else:
            raise ValueError("An attempt to write to an unopened file has been made.")

    def read_all(self):
        # This will read all of the information in a file and return it as one large string
        if self.isopen:
            self.file.seek(0)
            return self.file.read()
        else:
            raise ValueError("An attempt has been made to read from an unopened file.")

    @staticmethod
    def user_folder():
        # Returns the path to the user's folder.
        return os.path.expanduser('~')

    @staticmethod
    def user_documents_folder():
        # Returns the path to the user's document's folder
        return os.path.join(os.path.expanduser('~'), 'Documents')

    def debug(self):
        # Doesn't do anything yet.
        self.exists = self.exists
        # TODO: Make this test EVERYTHING


def debug():
    startup_debug_parser = ReusableTextParser("", "", 300)
    startup_debug_parser.debug(True)
    debug_file = File(os.path.join(File.user_documents_folder(), "ROBCO_PM", "Debug.txt"))
    debug_file.debug()


def is_complex_password(potential_password):
    complexity = 0
    potential_password_ascii_array = ReusableTextParser.convert_string_to_int_array(potential_password)
    number_discovered = False
    lower_case_discovered = False
    upper_case_discovered = False
    number_ascii_array = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57]
    lower_case_ascii_array = [97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
                              110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122]
    upper_case_ascii_array = [65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
                              80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90]
    for i in range(0, len(potential_password_ascii_array)):
        if i in number_ascii_array and not number_discovered:
            complexity += 1
        elif i in lower_case_ascii_array and not lower_case_discovered:
            complexity += 1
        elif i in upper_case_ascii_array and not upper_case_discovered:
            complexity += 1
        elif i not in number_ascii_array and i not in lower_case_ascii_array and i not in upper_case_ascii_array:
            complexity += 1
    if complexity >= 3 and len(potential_password) >= 8:
        return True
    else:
        return False


def exit_function():
    exit()


def set_settings():
    settings_file = File(os.path.join(File.user_documents_folder(), "ROBCO_PM", "settings.ini"))
    if not settings_file.exists:
        settings_file.create()
    settings_file.open()
    settings_file.write_all("")


def get_settings():
    settings_file = File(os.path.join(File.user_documents_folder(), "ROBCO_PM", "settings.ini"))
    if not settings_file.exists:
        set_settings()
        return get_settings()
    settings_file.open()
    settings = settings_file.read_all()
    settings_file.close()
    if not valid_settings(settings):
        reinitialize_settings = input("The settings file is not valid.\n"
                                      "Would you like to restore settings to their default?\n"
                                      "Entering N will cause this program to close.\n"
                                      " Y/N: ")
        while not reinitialize_settings.upper() == "N" and not reinitialize_settings.upper() == "Y":
            reinitialize_settings = input("Your input was not acceptable. Please either enter \"Y\" or \"N\": ")
        if reinitialize_settings.upper() == "Y":
            set_settings()
            return get_settings()
        else:
            exit()
    else:
        return settings


def valid_settings(potentially_invalid_settings):
    if potentially_invalid_settings != "":
        return False
    else:
        return True


"""debug()"""
settings = get_settings()
command_interpreter = CommandInterpreter(print)
command_interpreter.add_command("EXIT", exit_function, "exits the program.")
command_interpreter.describe_functions()
while True:
    command_interpreter.run_command(input("User>"))
