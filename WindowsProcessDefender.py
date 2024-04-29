import json
import os
import sys
import time
import tkinter.filedialog as tk_filedialog
import tkinter.font as tk_font
from base64 import b64decode
from subprocess import Popen, PIPE, CREATE_NO_WINDOW, DETACHED_PROCESS, CREATE_NEW_PROCESS_GROUP
from threading import Thread
from tkinter import Tk, ttk, BooleanVar, Menu

from psutil import pids, Process
from win32com.client import Dispatch
from win32gui import FindWindow, ShowWindow

from nmico import icon as nmico_data

WPD_DATA = 'C:/ProgramData/Windows Process Defender/data.json'
WPD_DATA_PATH = 'C:/ProgramData/Windows Process Defender'
WPD_ICON = 'C:/ProgramData/Windows Process Defender/icon.ico'


def has_wpd_process():
    hwnd = FindWindow(None, "Windows Process Defender")
    if hwnd:
        try:
            ShowWindow(hwnd, 5)
            return True
        except Exception as e:
            print(e)
            return False
    return False


def is_startup():
    if "--startup_visit" in sys.argv:
        return True
    return False


def turn_schedule(state: bool, result_var: BooleanVar):
    add_scd_cmd = f'schtasks /create /tn WPDStartup /tr "{sys.argv[0]} --startup_visit" /sc ONLOGON /rl highest /f'
    del_sch_cmd = f'schtasks /delete /tn WPDStartup /f'
    cmd = add_scd_cmd if state else del_sch_cmd
    p = Popen(cmd, stdin=PIPE, creationflags=CREATE_NO_WINDOW)
    p.communicate(input=b'y\n')
    result_var.set(get_startup_state())


def get_startup_state():
    chk_cmd = f'schtasks /query /tn WPDStartup'
    return bool("".join(os.popen(chk_cmd).readlines()))


def write_features(data: dict):
    wpd_data['features'] = data
    with open(WPD_DATA, 'w') as file:
        json.dump(wpd_data, file, indent=4)


def read_json(filename):
    with open(filename, 'r') as file:
        return json.load(file)


def start_protecting_process():
    previous_pids_dict = {}
    while continue_defending:
        previous_pids_dict = scan_process(previous_pids_dict)
        time.sleep(1)


def scan_process(pids_dict: dict):
    current_pids = pids()

    if set(current_pids) == set(pids_dict.keys()):  # pass
        return current_pids

    for c_pid in current_pids:  # add new pids
        if c_pid in pids_dict.keys():
            continue
        try:
            if c_pid in [0, 4]:
                continue
            pids_dict[c_pid] = Process(c_pid).exe()
        except Exception as e:
            print(e)

    removed_pids = []  # remove old pids
    for p_pid in pids_dict.keys():
        if p_pid in current_pids:
            continue
        removed_pids.append(p_pid)
    for r_pid in removed_pids:
        del pids_dict[r_pid]

    for target in features.keys():
        if os.path.normpath(target) not in pids_dict.values() and features[target]:
            try:
                Popen([os.path.basename(target)], cwd=os.path.dirname(target), shell=True,
                      creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
            except Exception as e:
                print(f"Error starting process {target}: {e}")

    return pids_dict


def mk_ui(hide_root):
    global features

    def save_data():
        global features
        features = {}
        for _t in targets_booleanvar_dict.keys():
            features[_t] = targets_booleanvar_dict[_t].get()
        write_features(features)
        save_btn.config(text="Success!")
        root.after(1000, lambda: save_btn.config(text="Save & Apply"))

    def add_lines(new_items_dict: dict):
        # add new columns into the list, and then place the targets in order
        for _index, _target in enumerate(new_items_dict.keys()):
            targets_booleanvar_dict[_target] = BooleanVar()
            targets_booleanvar_dict[_target].set(new_items_dict[_target])
            targets_checkbutton_dict[_target] = ttk.Checkbutton(
                target_frame, text=_target, variable=targets_booleanvar_dict[_target])
            targets_remove_button_dict[_target] = ttk.Button(
                target_frame, text='Remove', command=lambda _tar=_target: remove_line(_tar))
        for _index, _target in enumerate(targets_checkbutton_dict.keys()):
            targets_checkbutton_dict[_target].grid(
                row=_index, column=0, columnspan=2, padx=5, pady=2, sticky='NSEW')
            targets_remove_button_dict[_target].grid(row=_index, column=2, padx=2, pady=2, sticky='NSEW')

        add_targets_button.grid(row=1 + len(targets_checkbutton_dict), column=0, columnspan=3, padx=10, ipadx=5,
                                pady=5, sticky='NSEW')
        close_btn.grid(row=2 + len(targets_checkbutton_dict), column=0, padx=10, ipadx=5, pady=5, sticky='NSEW')
        save_btn.grid(row=2 + len(targets_checkbutton_dict), column=1, columnspan=2, padx=10, ipadx=25, pady=5,
                      sticky='NSEW')
        resize_root()

    def remove_line(_target):
        targets_checkbutton_dict[_target].destroy()
        targets_remove_button_dict[_target].destroy()
        targets_remove_button_dict.pop(_target)
        targets_checkbutton_dict.pop(_target)
        targets_booleanvar_dict.pop(_target)
        resize_root()

    def resolved_shortcut(lnk_path):
        # To tell if the target of the shortcut is a .exe file. If yes, return the target path, else return None.
        shell = Dispatch("WScript.Shell")
        _target_path = shell.CreateShortCut(lnk_path).Targetpath
        if _target_path.lower().endswith('.exe'):
            return _target_path
        return None

    def processed_exe_names(filenames) -> dict:
        # process the .exe and .lnk files received and return the dict of processed .exe files
        processed_files = {}
        for filename in filenames:
            if (filename.lower().endswith('.exe') or
                filename.lower().endswith('.lnk') and (filename := resolved_shortcut(filename))) \
                    and filename not in targets_checkbutton_dict.keys():
                processed_files[filename] = True
        return processed_files

    def add_targets():
        files_path = tk_filedialog.askopenfilenames(
            title='Select files to protect', filetypes=[('Executable files', '*.exe'), ('Shortcut files', '*.lnk')])
        add_lines(processed_exe_names(files_path))

    def resize_root():
        root.rowconfigure(1, weight=1, minsize=31 * int(bool(len(targets_checkbutton_dict))) - 5)
        root.minsize(width=600, height=31 * len(targets_checkbutton_dict) + 105)
        root.geometry(f"600x{31 * len(targets_checkbutton_dict) + 105}")

    def exit_program():
        global continue_defending
        continue_defending = False
        root.quit()
        root.destroy()

    root = Tk()
    if hide_root:
        root.withdraw()
    root.title('Windows Process Defender')
    root.iconbitmap(WPD_ICON)
    root.protocol('WM_DELETE_WINDOW', root.withdraw)
    tkfont = tk_font.nametofont("TkDefaultFont")
    tkfont.config(family='Microsoft YaHei UI')
    root.option_add("*Font", tkfont)

    targets_booleanvar_dict = {}
    targets_checkbutton_dict = {}
    targets_remove_button_dict = {}

    target_notice_label = ttk.Label(root, text='Targets:')
    target_notice_label.grid(row=0, column=0, padx=10, pady=5, sticky='NSEW')
    target_frame = ttk.Frame(root)
    target_frame.grid(row=1, column=0, columnspan=2, padx=8, sticky='NSEW')
    target_frame.columnconfigure(0, weight=1, minsize=200)

    add_targets_button = ttk.Button(root, text='+ Add targets', command=add_targets)
    close_btn = ttk.Button(root, text='Exit', command=exit_program)
    save_btn = ttk.Button(root, text='Save & Apply', command=save_data)
    root.bind_all('<Return>', lambda event: save_data())
    root.bind_all('<Control-s>', lambda event: save_data())
    root.grid_columnconfigure(1, weight=1, minsize=200)

    add_lines(features)

    main_menu = Menu(root)
    option_menu = Menu(main_menu, tearoff=False)
    is_startup_set = BooleanVar(value=get_startup_state())
    option_menu.add_checkbutton(label="Start when any user logs in", variable=is_startup_set,
                                command=lambda: Thread(turn_schedule(is_startup_set.get(), is_startup_set)).start())
    main_menu.add_cascade(label="Options", menu=option_menu)
    root.config(menu=main_menu)
    root.mainloop()


def main():
    global features, wpd_data, continue_defending
    if has_wpd_process():
        return

    if not os.path.isdir(WPD_DATA_PATH):
        os.makedirs(WPD_DATA_PATH)
    if not os.path.isfile(WPD_DATA):
        with open(WPD_DATA, 'w') as f:
            json.dump({}, f, indent=4)
    if not os.path.isfile(WPD_ICON):
        with open(WPD_ICON, "wb") as f:
            f.write(b64decode(nmico_data))

    wpd_data = read_json(WPD_DATA)
    if not wpd_data.get("features"):
        wpd_data["features"] = {}
        write_features(wpd_data["features"])
    features = wpd_data["features"]

    continue_defending = True

    protector_thread = Thread(target=start_protecting_process, daemon=True)
    protector_thread.start()

    mk_ui(hide_root=is_startup())


if __name__ == '__main__':
    main()
