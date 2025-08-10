import pymysql, bcrypt

SERVER = "localhost"
USER = "core"
PASSWORD = "core"
DATABASE = "c2_database"




def AddUsers(username, password):
    connection = pymysql.connect(host=SERVER, 
                                user=USER, 
                                password=PASSWORD, 
                                database=DATABASE)
    cur = connection.cursor()

    salt = bcrypt.gensalt(12)
    hashed_pw = bcrypt.hashpw(password.encode(), salt=salt)
    
    
    cur.execute("INSERT INTO Operators (username, password) VALUES (%s, %s)", 
                (username, hashed_pw))

    connection.commit()

    cur.close()
    connection.close()



users = {
    "usernames":[],
    "passwords":[]
}

for username, password in zip(users["usernames"], users["passwords"]):
    AddUsers(username, password)





