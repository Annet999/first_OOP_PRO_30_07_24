import hashlib
import uuid

class User:
    # Базовый класс, представляющий пользователя.
    users = []# Список для хранения всех пользователей

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = User.hash_password(password)
        User.users.append(self)


    @staticmethod
    def hash_password(password):
        salt = uuid.uuid4().hex
        return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt                          
        
    @staticmethod
    def check_password(stored_password, provided_password):
        password, salt = stored_password.split(':')
        return password == hashlib.sha256(salt.encode() + provided_password.encode()).hexdigest()

    def get_details(self):
        return {
            "username": self.username,         
            "email": self.email
        } 
        

class Customer(User):
# Класс представляющий клиента, наследующий класс User.
    def __init__(self, username, email, password, address):
        super().__init__(username, email, password)
        self.address = address

    def get_details(self):
        details = super().get_details()
        details["address"] = self.address
        return details   


class Admin(User):

    # Класс, представляющий администратора, дочерний класс User.

    def __init__(self, username, email, password, admin_level):
        super().__init__(username, email, password)
        self.admin_level = admin_level

                                         
    def get_details(self):
        details = super().get_details()
        details["admin_level"] = self.admin_level
        return details

    @staticmethod
    def list_users():

        # Выводит список всех пользователей.
        
        return [user.get_details() for user in User.users]


    @staticmethod
    def delete_user(username):

        # удаляет пользователя по имени пользователя.

        user_to_delete = None 
        for user in User.users:
            if user.username == username:
                user_to_delete = user
                break
        if user_to_delete:
            User.users.remove(user_to_delete)
            return True
        return False


class AuthenticationService:
    # Сервис для управления регистрацией и аутетификацией пользователей. 
    def __init__(self):
        self.current_user = None

    def register(self, user_class, username, email, password, *args):

        # Регистрация нового пользователя.

        if any(user.username == username for user in User.users):
            return "Username already taken."

        if user_class == Customer:
            new_user = Customer(username, email, password, *args)
        elif user_class == Admin:
            new_user = Admin(username, email, password, *args)    
        else:
            return "Invalid user class."
        
        return f"User {username} registered successfully."
    

    def login(self, username, password):

        # Аутентификация пользователя.
        for user in User.users:
            if user.username == username and User.check_password(user.password, password):
                self.current_user = user
                return f"User {username} logged in successfully."
        return "Invalid username or password."

    def logout(self):
        # Выход пользователя из системы.
        if self.current_user:
            user = self.current_user.username
            self.current_user = None
            return f"User {user} logged out successfully."
        return "No user is currently logged in."

    def get_current_user(self):
        # Возвращает текущего вошедшего пользователя.

        if self.current_user:
            return self.current_user.get_details()
        return "No user is currently logged in." 


# Пример использования    

auth_service = AuthenticationService()

# Регистрация пользователей
print(auth_service.register(Customer, "john_doe", "john@example.com", "password123", "123 Elm Street"))
print(auth_service.register(Admin, "admin", "admin@example.com", "adminpass", 1))

# Попытка повторной регистрации
print(auth_service.register(Customer, "john_doe", "john@example.com", "password123", "123 Elm Street"))

# Логин пользователя
print(auth_service.login("john_doe", "password123"))
print(auth_service.get_current_user())

# Логин администратора
print(auth_service.login("admin", "adminpass"))
print(auth_service.get_current_user())

# Логаут
print(auth_service.logout())
print(auth_service.get_current_user())

# Просмотр списка пользователей (администратором)
print(Admin.list_users())

# Удаление пользователя (администратором)
print(Admin.delete_user("john_doe"))

# Просмотр списка пользователей после удаления
print(Admin.list_users())







