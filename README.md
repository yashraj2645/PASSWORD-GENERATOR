# PASSWORD-GENERATOR
from tkinter import *
from tkinter import messagebox, ttk
from random import choice, shuffle
import string

# App setup
root = Tk()
root.title("🔐 Advanced Password Generator")
root.geometry("600x600")
root.config(bg="#1e1e2e")
root.resizable(False, False)

# Variables
password_var = StringVar()
length_var = IntVar(value=12)
auto_copy = BooleanVar(value=True)
show_pass = BooleanVar(value=False)
include_letters = BooleanVar(value=True)
include_digits = BooleanVar(value=True)
include_symbols = BooleanVar(value=True)
exclude_similar = BooleanVar(value=False)
exclude_ambiguous = BooleanVar(value=False)
history = []

# Functions
def generate_password():
    length = length_var.get()
    if length < 4:
        messagebox.showwarning("Too Short", "Password length must be at least 4 characters.")
        return

    letters = string.ascii_letters
    digits = string.digits
    symbols = "!@#$%^&*()-_=+<>"

    if exclude_similar.get():
        letters = letters.translate(str.maketrans('', '', 'Il1O0'))
        digits = digits.translate(str.maketrans('', '', '01'))

    if exclude_ambiguous.get():
        symbols = symbols.translate(str.maketrans('', '', '{}[]()/\\\'"`~,;:.' ))

    char_pool = ''
    if include_letters.get(): char_pool += letters
    if include_digits.get(): char_pool += digits
    if include_symbols.get(): char_pool += symbols

    if not char_pool:
        messagebox.showerror("No Character Set", "Please select at least one character type.")
        return

    password = ''.join(choice(char_pool) for _ in range(length))
    password_var.set(password)
    history.append(password)
    update_strength_indicator(password)

    if auto_copy.get():
        root.clipboard_clear()
        root.clipboard_append(password)
        root.update()

def update_strength_indicator(password):
    length = len(password)
    has_letters = any(c.isalpha() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(c in string.punctuation for c in password)

    score = sum([has_letters, has_digits, has_symbols]) + (length >= 12)

    # Update progress bar based on strength
    progress_bar['value'] = score * 33

    if score <= 2:
        strength_label.config(text="Weak 🔴", fg="red", bg="lightcoral")
    elif score == 3:
        strength_label.config(text="Medium 🟠", fg="orange", bg="lightyellow")
    else:
        strength_label.config(text="Strong 🟢", fg="lime", bg="lightgreen")

def toggle_visibility():
    if show_pass.get():
        entry_password.config(show="")
    else:
        entry_password.config(show="*")

def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(password_var.get())
    root.update()
    messagebox.showinfo("Copied", "Password copied to clipboard.")

def reset_all():
    password_var.set("")
    length_var.set(12)
    strength_label.config(text="", bg="#1e1e2e")
    progress_bar['value'] = 0
    history.clear()

def show_history():
    if not history:
        messagebox.showinfo("No History", "No password has been generated yet.")
    else:
        history_window = Toplevel(root)
        history_window.title("Password History")
        history_window.geometry("400x300")

        history_text = Text(history_window, wrap=WORD, height=12, width=40, font=("Helvetica", 12))
        history_text.pack(padx=10, pady=10)

        for password in history[-10:]:
            history_text.insert(END, password + "\n")
        
        history_text.config(state=DISABLED)

def copy_all_history():
    if not history:
        messagebox.showinfo("No History", "No history available to copy.")
        return

    history_str = "\n".join(history)
    root.clipboard_clear()
    root.clipboard_append(history_str)
    root.update()
    messagebox.showinfo("History Copied", "Password history copied to clipboard.")

# UI Layout
title = Label(root, text="🔐 Password Generator", bg="#1e1e2e", fg="white", font=("Helvetica", 20, "bold"))
title.pack(pady=10)

frame_controls = Frame(root, bg="#1e1e2e")
frame_controls.pack(pady=5)

Label(frame_controls, text="Length:", bg="#1e1e2e", fg="white", font=("Helvetica", 12)).grid(row=0, column=0, sticky="w")
Spinbox(frame_controls, from_=4, to=64, textvariable=length_var, width=5, font=("Helvetica", 12)).grid(row=0, column=1)

Checkbutton(frame_controls, text="Letters", variable=include_letters, bg="#1e1e2e", fg="white").grid(row=1, column=0, sticky="w")
Checkbutton(frame_controls, text="Digits", variable=include_digits, bg="#1e1e2e", fg="white").grid(row=1, column=1, sticky="w")
Checkbutton(frame_controls, text="Symbols", variable=include_symbols, bg="#1e1e2e", fg="white").grid(row=1, column=2, sticky="w")
Checkbutton(frame_controls, text="Exclude Similar (1l0O)", variable=exclude_similar, bg="#1e1e2e", fg="white").grid(row=2, column=0, columnspan=2, sticky="w")
Checkbutton(frame_controls, text="Exclude Ambiguous", variable=exclude_ambiguous, bg="#1e1e2e", fg="white").grid(row=3, column=0, columnspan=2, sticky="w")

frame_password = Frame(root, bg="#1e1e2e")
frame_password.pack(pady=10)

entry_password = Entry(frame_password, textvariable=password_var, font=("Helvetica", 16), width=30, show="*", justify="center")
entry_password.pack(pady=10)

Checkbutton(frame_password, text="Show Password", variable=show_pass, command=toggle_visibility, bg="#1e1e2e", fg="white").pack()

strength_label = Label(frame_password, text="", bg="#1e1e2e", font=("Helvetica", 12, "bold"))
strength_label.pack(pady=10)

progress_bar = ttk.Progressbar(frame_password, orient=HORIZONTAL, length=300, mode="determinate")
progress_bar.pack(pady=5)

frame_buttons = Frame(root, bg="#1e1e2e")
frame_buttons.pack(pady=15)

Button(frame_buttons, text="Generate", command=generate_password, bg="#4CAF50", fg="white", font=("Helvetica", 12), width=15).grid(row=0, column=0, padx=10)
Button(frame_buttons, text="Copy", command=copy_to_clipboard, bg="#2196F3", fg="white", font=("Helvetica", 12), width=15).grid(row=0, column=1, padx=10)

frame_misc = Frame(root, bg="#1e1e2e")
frame_misc.pack()

Checkbutton(frame_misc, text="Auto Copy to Clipboard", variable=auto_copy, bg="#1e1e2e", fg="white").pack()
Button(frame_misc, text="Show History", command=show_history, bg="#FF9800", fg="white", font=("Helvetica", 10), width=15).pack(pady=5)
Button(frame_misc, text="Copy All History", command=copy_all_history, bg="#FF5722", fg="white", font=("Helvetica", 10), width=15).pack(pady=5)
Button(frame_misc, text="Reset", command=reset_all, bg="#f44336", fg="white", font=("Helvetica", 10), width=15).pack()

# Start the GUI
root.mainloop()
