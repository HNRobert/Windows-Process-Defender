import json
import os
import sys
import time
import tkinter as tk
import tkinter.filedialog as tk_filedialog
import tkinter.font as tk_font
from base64 import b64decode
from subprocess import Popen, PIPE, CREATE_NO_WINDOW
from threading import Thread
from tkinter import Tk, ttk

from psutil import pids, Process
from win32com.client import Dispatch
from win32gui import FindWindow, ShowWindow

from nmico import icon as nmico_data

WPD_DATA = 'C:/ProgramData/Windows Process Defender/data.json'
WPD_DATA_PATH = 'C:/ProgramData/Windows Process Defender'
WPD_ICON = 'C:/ProgramData/Windows Process Defender/icon.ico'


def has_wpd_process():
    hwnd = FindWindow(None, "Windows Process Defender Settings")
    if hwnd and not is_startup():
        try:
            ShowWindow(hwnd, 5)
            return True
        except Exception as e:
            print(e)
            return False
    elif hwnd:  # Is running, but on startup, then don't show its window
        return True
    return False


def is_startup():
    if "--startup_visit" in sys.argv:
        return True
    return False


def turn_schedule(state: bool, result_var: tk.BooleanVar):
    set_startup_cmd = f'schtasks /create /tn WPDStartup /tr "\\"{sys.argv[0]}\\" \\"--startup_visit\\"" /sc ONLOGON /rl highest /f'
    rm_startup_cmd = f'schtasks /delete /tn WPDStartup /f'
    cmd = set_startup_cmd if state else rm_startup_cmd
    p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, creationflags=CREATE_NO_WINDOW)
    stdout, stderr = p.communicate()
    if p.returncode == 0:
        print("Success:")
        print(stdout.decode())
    else:
        print("Error:")
        print(stderr.decode())
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
            c_exe = Process(c_pid).exe()
            if c_exe == "C:\\Windows\\System32\\consent.exe":
                return pids_dict
            pids_dict[c_pid] = c_exe
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
        if os.path.normpath(target) not in pids_dict.values() and features[target][0]:
            args_cmd = ''.join([f' \\"{param}\\"' for param in features[target][1].split() if param])
            add_scd_cmd = f'schtasks /create /tn WPDRun /tr "\\"{os.path.normpath(target)}\\"{args_cmd}" /sc ONLOGON /rl highest /f'
            run_scd_cmd = f'schtasks /run /tn WPDRun'
            del_sch_cmd = f'schtasks /delete /tn WPDRun /f'
            try:
                for cmd in [add_scd_cmd, run_scd_cmd, del_sch_cmd]:
                    p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, creationflags=CREATE_NO_WINDOW)
                    stdout, stderr = p.communicate()
                    if p.returncode == 0:
                        print("Success:")
                        print(stdout.decode(errors='replace'))
                    else:
                        print("Error:")
                        print(stderr.decode(errors='replace'))
            except Exception as e:
                print(f"Error starting process {target}: {e}")

    return pids_dict


def mk_ui(hide_root):
    global features

    def save_data():
        global features
        features = {}
        for _t in targets_boolvar_dict.keys():
            features[_t] = [targets_boolvar_dict[_t].get(), targets_arg_dict[_t].get()]
        write_features(features)
        save_btn.config(text="Success!")
        root.after(1000, lambda: save_btn.config(text="Save & Apply"))

    def add_lines(new_items_dict: dict):
        # add new columns into the list, and then place the targets in order
        for _target in new_items_dict.keys():
            targets_boolvar_dict[_target] = tk.BooleanVar(value=new_items_dict[_target][0])
            targets_chkbutton_dict[_target] = ttk.Checkbutton(
                target_frame, text=_target, variable=targets_boolvar_dict[_target])
            targets_arg_dict[_target] = ttk.Entry(target_frame)
            targets_arg_dict[_target].insert(0, new_items_dict[_target][1])
            targets_remove_button_dict[_target] = ttk.Button(
                target_frame, text='Remove', command=lambda _tar=_target: remove_line(_tar))
        rearrange_lines()

    def rearrange_lines():
        for _index, _target in enumerate(targets_chkbutton_dict.keys()):
            targets_chkbutton_dict[_target].grid(
                row=_index + 1, column=0, padx=5, pady=2, sticky='NSEW')
            targets_arg_dict[_target].grid(row=_index + 1, column=1, padx=5, pady=2, sticky='NSEW')
            targets_remove_button_dict[_target].grid(row=_index + 1, column=2, padx=4, pady=2, sticky='NSEW')
        resize_root()

    def remove_line(_target):
        # Check if the button is in the "Sure?" state, if yes, delete the line and reset the button state
        if rm_button_state_dict.get(_target, False):
            # Delete the line and reset the button state
            targets_chkbutton_dict[_target].destroy()
            targets_remove_button_dict[_target].destroy()
            targets_arg_dict[_target].destroy()
            rm_button_state_dict.pop(_target, None)
            if _target in rm_button_timer_dict:
                root.after_cancel(rm_button_timer_dict[_target])
                rm_button_timer_dict.pop(_target)
            targets_remove_button_dict.pop(_target, None)
            targets_chkbutton_dict.pop(_target, None)
            targets_arg_dict.pop(_target, None)
            targets_boolvar_dict.pop(_target, None)
            rearrange_lines()
        else:
            # Set the button to "Sure?" state
            targets_remove_button_dict[_target].config(text="Sure?")
            rm_button_state_dict[_target] = True

            # Set a timer, if no more action in 3 sec then reset
            if _target in rm_button_timer_dict:
                root.after_cancel(rm_button_timer_dict[_target])

            rm_button_timer_dict[_target] = root.after(3000, reset_button, _target)

    def reset_button(_target):
        if _target in targets_remove_button_dict:
            targets_remove_button_dict[_target].config(text="Remove")
            rm_button_state_dict[_target] = False
            rm_button_timer_dict.pop(_target, None)

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
                    and filename not in targets_chkbutton_dict.keys():
                processed_files[filename] = [True, ""]
        return processed_files

    def add_targets():
        files_path = tk_filedialog.askopenfilenames(
            title='Select files to protect', filetypes=[('Executable files', '*.exe'), ('Shortcut files', '*.lnk')])
        add_lines(processed_exe_names(files_path))

    def resize_root():
        current_line_count = len(targets_chkbutton_dict)
        root.rowconfigure(1, weight=1, minsize=31 * int(bool(current_line_count)) - 5)
        root.minsize(width=800, height=140)
        root.geometry(
            f"{root.winfo_width()}x{min(max(24 * current_line_count + 190, root.winfo_height()), 600)}")
        for t_col in range(4):
            tar_col_list[t_col].grid_configure(rowspan=current_line_count + 1)
        for f_col in range(3):
            tar_final_row_sep[f_col].grid_configure(row=current_line_count + 1)

    def resize_canvas(event):
        # Update canvas' scroll region to match the actual size
        canvas_width = event.width
        target_canvas.itemconfig(canvas_window, width=canvas_width)
        target_canvas.config(scrollregion=target_canvas.bbox("all"))

    def processwheel(event):
        a = int(-event.delta)
        if a > 0:
            target_canvas.yview_scroll(1, tk.UNITS)
        else:
            target_canvas.yview_scroll(-1, tk.UNITS)

    def exit_program():
        global continue_defending
        continue_defending = False
        root.quit()
        root.destroy()

    root = Tk()
    if hide_root:
        root.withdraw()
    root.title('Windows Process Defender Settings')
    root.iconbitmap(WPD_ICON)
    root.protocol('WM_DELETE_WINDOW', root.withdraw)
    root.geometry("600x100")
    """
    root.attributes('-topmost', True)
    root.attributes('-topmost', False)
    root.update_idletasks()
    """
    tkfont = tk_font.nametofont("TkDefaultFont")
    tkfont.config(family='Microsoft YaHei UI')
    root.option_add("*Font", tkfont)

    targets_boolvar_dict = {}
    targets_chkbutton_dict = {}
    targets_arg_dict = {}
    targets_remove_button_dict = {}

    rm_button_state_dict = {}
    rm_button_timer_dict = {}

    target_notice_label = ttk.Label(root, text='Targets:')
    target_notice_label.grid(row=0, column=0, padx=10, pady=5, sticky='NSEW')

    target_label_frame = tk.LabelFrame(root, relief=tk.GROOVE)
    target_label_frame.grid(row=1, column=0, padx=11, columnspan=2, sticky='NSEW')
    target_label_frame.bind_all("<MouseWheel>", processwheel)
    target_label_frame.columnconfigure(0, weight=1, minsize=200)
    target_label_frame.rowconfigure(0, weight=1)

    target_canvas = tk.Canvas(target_label_frame)
    target_canvas.config(highlightthickness=0)
    target_canvas.grid(row=0, column=0, columnspan=1, sticky="NSEW")

    target_frame = ttk.Frame(target_canvas)
    target_frame.columnconfigure(0, weight=1, minsize=200)

    target_canvas_scrollbar = ttk.Scrollbar(target_label_frame, orient=tk.VERTICAL)
    target_canvas_scrollbar.grid(row=0, column=1, sticky="NSEW")
    target_canvas_scrollbar.config(command=target_canvas.yview)

    target_canvas.config(yscrollcommand=target_canvas_scrollbar.set)
    canvas_window = target_canvas.create_window((0, 0), window=target_frame, anchor='nw')
    target_canvas.bind("<Configure>", resize_canvas)

    tar_col_list = []
    tar_final_row_sep = []
    for col in range(4):
        tar_col_list.append(ttk.Separator(target_frame, orient="vertical"))
        tar_col_list[-1].grid(row=0, rowspan=1, column=col, sticky='NSEW')
    for col in range(6):
        tar_first_row_sep = ttk.Separator(target_frame, orient='horizontal')
        tar_first_row_sep.grid(row=col // 3, column=col % 3, padx=1, sticky='NSEW')
    for col in range(3):
        tar_final_row_sep.append(ttk.Separator(target_frame, orient="horizontal"))
        tar_final_row_sep[-1].grid(row=0, column=col, padx=1, sticky='NSEW')

    targets_name_label = ttk.Label(target_frame, text="Executable files' path")
    targets_name_label.grid(row=0, column=0, pady=5)
    targets_arg_label = ttk.Label(target_frame, text="Args")
    targets_arg_label.grid(row=0, column=1, pady=5)
    targets_del_label = ttk.Label(target_frame, text="Remove")
    targets_del_label.grid(row=0, column=2, pady=5)

    add_targets_button = ttk.Button(root, text='+ Add targets', command=add_targets)
    add_targets_button.grid(row=2, column=0, columnspan=3, padx=10, ipadx=5,
                            pady=5, sticky='NSEW')
    close_btn = ttk.Button(root, text='Exit', command=exit_program)
    close_btn.grid(row=3, column=0, padx=10, ipadx=5, pady=5, sticky='NSEW')
    save_btn = ttk.Button(root, text='Save & Apply', command=save_data)
    save_btn.grid(row=3, column=1, columnspan=2, padx=10, ipadx=25, pady=5,
                  sticky='NSEW')
    root.bind_all('<Return>', lambda event: save_data())
    root.bind_all('<Control-s>', lambda event: save_data())
    root.grid_columnconfigure(1, weight=1, minsize=200)

    add_lines(features)

    main_menu = tk.Menu(root)
    option_menu = tk.Menu(main_menu, tearoff=False)
    is_startup_set = tk.BooleanVar(value=get_startup_state())
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
