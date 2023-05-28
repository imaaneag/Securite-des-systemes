import customtkinter
from tkinter import *
import hashlib

customtkinter.set_appearance_mode("dark")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

app = customtkinter.CTk()
app.geometry("900x600")
app.title("Hachage")

frame = customtkinter.CTkFrame(master=app, width=900, height=600)
frame.pack(pady=20, padx=60, expand=True)

frame_1 = customtkinter.CTkFrame(master=frame, height=430)
frame_1.place(x=20, y=30)

frame_21 = customtkinter.CTkFrame(master=frame, width= 510)
frame_21.place(x=250, y=30)

frame_22 = customtkinter.CTkFrame(master=frame, width= 510)
frame_22.place(x=250, y=260)

########################## functions declaration#########################################################

def close_window():
    app.quit()
    
def hash2(b):
    hash2_value.set(b)

def hash1(b):
    hash1_value.set(b)

def get_value_choix():
    print(choix_function.get())

def input_msg_1():
    user_input = msg_1.get("1.0", "end").strip()
    print(user_input)
    
def input_msg_2():
    user_input = msg_2.get("1.0", "end").strip()
    print(user_input)

def copier() :
    msg_2.delete("1.0", "end")
    msg_2.insert("1.0", msg_1.get("1.0", "end").strip())
    
def hashing1():
    f = choix_function.get()
    user_input = msg_1.get("1.0", "end").strip()
    
    if (f == 'SHA1') :
        result = hashlib.sha1(user_input.encode())
    if (f == 'SHA224') :
        result = hashlib.sha224(user_input.encode())
    if (f == 'SHA256') :
        result = hashlib.sha256(user_input.encode())
    if (f == 'SHA384') :
        result = hashlib.sha384(user_input.encode())
    if (f == 'SHA512') :
        result = hashlib.sha512(user_input.encode())
    if (f == 'BLAKE2b') :
        result = hashlib.blake2b(user_input.encode())
    if (f == 'BLAKE2s') :
        result = hashlib.blake2s(user_input.encode())
    if (f == 'MD5') :
        result = hashlib.md5(user_input.encode())
        
    hash1(result.hexdigest()) 
    
    rep_1 = customtkinter.CTkLabel(master=frame_21, justify=customtkinter.LEFT, text="Hash généré \navec succès !")
    rep_1.place(x=405, y=100)
    
def hashing2():
    f = choix_function.get()
    user_input = msg_2.get("1.0", "end").strip()
    
    if (f == 'SHA1') :
        result = hashlib.sha1(user_input.encode())
    if (f == 'SHA224') :
        result = hashlib.sha224(user_input.encode())
    if (f == 'SHA256') :
        result = hashlib.sha256(user_input.encode())
    if (f == 'SHA384') :
        result = hashlib.sha384(user_input.encode())
    if (f == 'SHA512') :
        result = hashlib.sha512(user_input.encode())
    if (f == 'BLAKE2b') :
        result = hashlib.blake2b(user_input.encode())
    if (f == 'BLAKE2s') :
        result = hashlib.blake2s(user_input.encode())
    if (f == 'MD5') :
        result = hashlib.md5(user_input.encode())
        
    hash2(result.hexdigest())
    
def verify() :
    if len(hash1_value.get())!=0 and len(hash2_value.get())!=0 :
        if(hash1_value.get() == hash2_value.get()) :
            rep_2 = customtkinter.CTkLabel(master=frame_22, justify=customtkinter.LEFT, text="Les deux Hashs \nsont identiques !")
        else :
            rep_2 = customtkinter.CTkLabel(master=frame_22, justify=customtkinter.LEFT, text="Les deux Hashs \nne sont pas \nidentiques !")
        rep_2.place(x=405, y=100)

########################## frame 1 #######################################################################

hashage = customtkinter.CTkLabel(master=frame_1, justify=customtkinter.LEFT, text="HACHAGE", font=("Helvetica", 36, "bold"))
hashage.place(x=10, y=10)

choix = customtkinter.CTkLabel(master=frame_1, justify=customtkinter.LEFT, text="Fonction de Hashage :")
choix.place(x=10, y=70)

choix_function = customtkinter.StringVar()
hash_function = customtkinter.CTkOptionMenu(frame_1, values=["SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "BLAKE2b", "BLAKE2s", "MD5"], variable=choix_function)
hash_function.place(x=10, y=100)
hash_function.set("Choisissez !")

valider_choix = customtkinter.CTkButton(master=frame_1, text="Valider mon choix", command=get_value_choix)
valider_choix.place(x=10, y=350)

########################## frame 21 ###################################################################

message_1 = customtkinter.CTkLabel(master=frame_21, justify=customtkinter.LEFT, text="Message :")
message_1.place(x=10, y=10)


msg1 = customtkinter.StringVar()
msg_1 = customtkinter.CTkTextbox(master=frame_21, width=350, height=70)
msg_1.place(x=10, y=40)



hashage_1 = customtkinter.CTkLabel(master=frame_21, justify=customtkinter.LEFT, text="Hash :")
hashage_1.place(x=10, y=120)


hash1_value = customtkinter.StringVar()
hash_1 = customtkinter.CTkEntry(master=frame_21, width=350, textvariable=hash1_value)
hash_1.place(x=10, y=150)


button_generer1 = customtkinter.CTkButton(master=frame_21, text="Générer", width=100, command=hashing1)
button_generer1.place(x=400, y=10)




########################## frame 22 ##################################################################

message_2 = customtkinter.CTkLabel(master=frame_22, justify=customtkinter.LEFT, text="Message à verifier :")
message_2.place(x=10, y=10)

msg_2 = customtkinter.CTkTextbox(master=frame_22, width=350, height=70)
msg_2.place(x=10, y=40)


hashage_2 = customtkinter.CTkLabel(master=frame_22, justify=customtkinter.LEFT, text="Hash (*) :")
hashage_2.place(x=10, y=120)


hash2_value = customtkinter.StringVar()
hash_2 = customtkinter.CTkEntry(master=frame_22, width=350, textvariable=hash2_value)
hash_2.place(x=10, y=150)


button_generer2 = customtkinter.CTkButton(master=frame_22, text="Générer", width=100, command=hashing2)
button_generer2.place(x=400, y=10)


##################################### hashing ############################################################
# Python 3 code to demonstrate the
# working of MD5 (string - hexadecimal)

 
# initializing string
#str2hash = "GeeksforGeeks"
 
# encoding GeeksforGeeks using encode()
# then sending to md5()
#result = hashlib.md5(str2hash.encode())
 
# printing the equivalent hexadecimal value.
#print("The hexadecimal equivalent of hash is : ", end ="")
#print(result.hexdigest())
###########################################################################################

button_copier = customtkinter.CTkButton(master=frame, text="Copier", command=copier)
button_copier.place(x=300, y=500)

button_verify = customtkinter.CTkButton(master=frame, text="Vérifier", command=verify)
button_verify.place(x=450, y=500)

button_close = customtkinter.CTkButton(master=frame, text="Terminer", command=close_window)
button_close.place(x=600, y=500)

app.mainloop()