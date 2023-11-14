import tkinter as tk
import hashlib

# Dados de usuários (nome de usuário, senha em hash)
users = {
    "user1": "81dc9bdb52d04dc20036dbd8313ed055",
    "user2": "ca8119f7d65b9448b246c76d23bb9a6e",
}

# Variáveis de controle
nunber = 0
nunber2 = 0
nunber3 = 0

def hash_password(password):
    md5 = hashlib.md5()
    md5.update(password.encode('utf-8'))
    hashed_password = md5.hexdigest()
    return hashed_password

def Create():
    username = create_username_entry.get()
    password = create_password_entry.get()
    
    if username in users:
        result_label_create.config(text="Nome de usuário já existe!")
    else:
        users[username] = hash_password(password)
        result_label_create.config(text="Conta criada com sucesso!")

def login():
    userlogin = username_entry.get()
    psuserlogin = password_entry.get()
    
    if userlogin not in users:
        result_label_login.config(text="Este nome de usuário não existe!")
    elif users[userlogin] == hash_password(psuserlogin):
        show_welcome_page()
    else:
        result_label_login.config(text="Nome de usuário ou senha incorretos.")

def show_welcome_page():
    # Limpar a tela de login
    frame.pack_forget()
    
    # Criar uma nova tela de boas-vindas
    welcome_frame = tk.Frame(root)
    welcome_frame.pack(padx=20, pady=20)
    
    welcome_label = tk.Label(welcome_frame, text="Bem-vindo ao sistema!")
    welcome_label.pack()
    logout_button = tk.Button(welcome_frame, text="Logout", command=logout)
    
    global nunber2
    if nunber2 == 0:
        nunber2 = 1
        logout_button.pack()

    security_tips_button = tk.Button(welcome_frame, text="Dicas de Segurança", command=show_security_tips)
    security_tips_button.pack()

def show_security_tips():
    global nunber  # Declare a variável como global
    if nunber == 0:
        nunber = 1  # A dica de segurança está aberta

        # Limpar a tela de boas-vindas
        welcome_frame.pack_forget()
    
        # Criar uma nova tela com dicas de segurança
        security_tips_frame = tk.Frame(root)
        security_tips_frame.pack(padx=20, pady=20)
    
        security_tips_label = tk.Label(security_tips_frame, text="Dicas de Segurança Digital:")
        security_tips_label.pack()
   
        tips_text = "1. Mantenha suas senhas seguras e não compartilhe com ninguém.\n" \
                    "   Use senhas exclusivas para cada conta.\n\n" \
                    "2. Crie senhas fortes com uma combinação de letras maiúsculas, minúsculas, números e caracteres especiais.\n" \
                    "   Evite informações pessoais óbvias.\n\n" \
                    "3. Este sistema de login utiliza hashes MD5 para segurança básica.\n" \
                    "   Em aplicações reais, use métodos de criptografia mais seguros, como o bcrypt.\n\n" \
                    "4. Esteja atento a golpes de phishing e nunca clique em links suspeitos ou forneça informações pessoais.\n" \
                    "   Verifique sempre a legitimidade das fontes online.\n"
    
        tips_label = tk.Label(security_tips_frame, text=tips_text, justify="left")
        tips_label.pack()
        
        back_button = tk.Button(security_tips_frame, text="Voltar", command=show_welcome_page)
        global nunber3
        if nunber3 == 0:
            nunber3 = 1
            back_button.pack()

def logout():
    # Limpar a tela de boas-vindas
    welcome_frame.pack_forget()
    
    # Mostrar a tela de login novamente
    frame.pack()

# Configuração da interface gráfica
root = tk.Tk()
root.title("Autenticação de Usuário")

frame = tk.Frame(root)
frame.pack(padx=20, pady=20)

username_label = tk.Label(frame, text="Nome de Usuário:")
username_label.grid(row=0, column=0, sticky="w")

username_entry = tk.Entry(frame)
username_entry.grid(row=0, column=1)

create_username_label = tk.Label(frame, text="Criar Nome de Usuário:")
create_username_label.grid(row=3, column=0, sticky="w")

create_username_entry = tk.Entry(frame)
create_username_entry.grid(row=3, column=1)

create_password_label = tk.Label(frame, text="Criar Senha:")
create_password_label.grid(row=4, column=0, sticky="w")

create_password_entry = tk.Entry(frame, show="*")
create_password_entry.grid(row=4, column=1)

password_label = tk.Label(frame, text="Senha:")
password_label.grid(row=1, column=0, sticky="w")

password_entry = tk.Entry(frame, show="*")
password_entry.grid(row=1, column=1)

create_button = tk.Button(frame, text="Criar", command=Create)
create_button.grid(row=5, columnspan=2)

login_button = tk.Button(frame, text="Login", command=login)
login_button.grid(row=2, columnspan=2)

result_label_login = tk.Label(frame, text="")
result_label_login.grid(row=3, columnspan=2)

result_label_create = tk.Label(frame, text="")
result_label_create.grid(row=6, columnspan=2)

# Variável para armazenar a tela de boas-vindas
welcome_frame = tk.Frame(root)

root.mainloop()
