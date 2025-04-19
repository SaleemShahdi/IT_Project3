import socket
import signal
import sys
import random

# Read a command line argument for the port where the server
# must run.
port = 8080
if len(sys.argv) > 1:
    port = int(sys.argv[1])
else:
    print("Using default port 8080")
hostname = socket.gethostname()
print("Hostname = " + hostname)


# Start a listening server socket on the port
sock = socket.socket()
sock.bind(('', port))
sock.listen(2)

### Contents of pages we will serve.
# Login form
login_form = """
   <form action = "http://%s" method = "post">
   Name: <input type = "text" name = "username">  <br/>
   Password: <input type = "text" name = "password" /> <br/>
   <input type = "submit" value = "Submit" />
   </form>
"""
# Default: Login page.
login_page = "<h1>Please login</h1>" + login_form
# Error page for bad credentials
bad_creds_page = "<h1>Bad user/pass! Try again</h1>" + login_form
# Successful logout
logout_page = "<h1>Logged out successfully</h1>" + login_form
# A part of the page that will be displayed after successful
# login or the presentation of a valid cookie
success_page = """
   <h1>Welcome!</h1>
   <form action="http://%s" method = "post">
   <input type = "hidden" name = "action" value = "logout" />
   <input type = "submit" value = "Click here to logout" />
   </form>
   <br/><br/>
   <h1>Your secret data is here:</h1>
"""

#### Helper functions
# Printing.
def print_value(tag, value):
    print("Here is the", tag)
    print("\"\"\"")
    print(value)
    print("\"\"\"")
    print()

# Signal handler for graceful exit
def sigint_handler(sig, frame):
    print('Finishing up by closing listening socket...')
    sock.close()
    sys.exit(0)
# Register the signal handler
signal.signal(signal.SIGINT, sigint_handler)


# TODO: put your application logic here!
# Read login credentials for all the users
# Read secret data of all the users
class Database:

    database = dict()

    def __init__(self):
        count = 0
        with open("passwords.txt", "r") as passwordsFile, open("secrets.txt", "r") as secretsFile:
            for line in passwordsFile:
                line = line.split()
                username = line[0]
                password = line[1]
                self.database[username] = [password, ""]
            for line in secretsFile:
                count = count + 1
                line = line.split()
                username = line[0]
                secret = line[1]
                if (self.database.get(username) == None):
                    print("Error: cannot give secret to username that hasn't been created yet")
                    print("       (username that has no password)")
                    print(f"""error caused by "{username} {secret}" in secrets file (at line {count})""")
                    print("Aborting...")
                    sys.exit(0)
                self.database[username][1] = secret

    def __str__(self):
        return self.database.__str__()
    
    def checkCredentials(self, username, password):
        if (self.database.get(username) == None):
            return False
        if (self.database[username][0] == password):
            return True
        return False

    def getSecret(self, username):
        return self.database[username][1]

def parseRequest(request):
    print("request = " + request)
    if request == "":
        return ("", "")
    if request == "action=logout":
        return ("logout", "logout") # just set username and password to logout if action=logout.
        # It may have been better to return separate variables for logout but the instructions didn't introduce
        # logout until after the authentication and cookie steps.
    request = request.split("&")
    print("request =", request)
    if ("username=" in request[0]):
        usernamePart = request[0]
        passwordPart = request[1]
    else:
        usernamePart = request[1]
        passwordPart = request[0]
    print("username part =", usernamePart)
    print("password part =", passwordPart)
    usernamePart = usernamePart.split("=")
    print("username part =", usernamePart)
    passwordPart = passwordPart.split("=")
    print("password part =", passwordPart)
    username = usernamePart[1]
    print("username =", username)
    password = passwordPart[1]
    print("password =", password)
    return (username, password)

def getCookie(header):
    if "Cookie" not in header:
        return ""
    print(header)
    header = header.splitlines()
    print(header)
    for i in range(0, len(header)):
        if "Cookie" in header[i]:
            header = header[i]
            break
    print(header)
    header = header.split("token=")
    print(header)
    cookie = header[1]
    print(cookie)
    return cookie

def getHost(header):
    header = header.splitlines()
    print(header)
    for i in range(0, len(header)):
        if "Host:" in header[i]:
            header = header[i]
            break
    print(header)
    header = header.split("Host: ")
    print(header)
    host = header[1]
    print(host)
    return host



        
database = Database()
databaseCookies = dict()
rand_val = -1
print(database)
firstTime = True



### Loop to accept incoming HTTP connections and respond.
while True:
    client, addr = sock.accept()
    print(addr) # delete later
    req = client.recv(1024)

    # Let's pick the headers and entity body apart
    header_body = req.decode().split('\r\n\r\n')
    headers = header_body[0]
    body = '' if len(header_body) == 1 else header_body[1]
    print_value('headers', headers)
    print_value('entity body', body)

    # TODO: Put your application logic here!
    # Parse headers and body and perform various actions
    

    

    # OPTIONAL TODO:
    # Set up the port/hostname for the form's submit URL.
    # If you want POSTing to your server to
    # work even when the server and client are on different
    # machines, the form submit URL must reflect the `Host:`
    # header on the request.
    # Change the submit_hostport variable to reflect this.
    # This part is optional, and might even be fun.
    # By default, as set up below, POSTing the form will
    # always send the request to the domain name returned by
    # socket.gethostname().
    # submit_hostport = "%s:%d" % (hostname, port) (was originally uncommented)
    submit_hostport = getHost(headers)
    username, password = parseRequest(body)
    cookie = getCookie(headers)
    print(databaseCookies)
    if cookie != "" and username == "logout" and password == "logout":
        html_content_to_send = logout_page % submit_hostport
        headers_to_send = f"Set-Cookie: token={cookie}; expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n"
        del databaseCookies[cookie]
    elif cookie != "" and databaseCookies.get(cookie) != None:
        html_content_to_send = (success_page % submit_hostport) + database.getSecret(databaseCookies[cookie])
        headers_to_send = ""
    elif cookie != "" and databaseCookies.get(cookie) == None:
        html_content_to_send = bad_creds_page % submit_hostport
        headers_to_send = ""
    elif username == "" and password == "":
        html_content_to_send = login_page % submit_hostport
        headers_to_send = ""
    elif username == "logout" and password == "logout":
        html_content_to_send = logout_page % submit_hostport
        headers_to_send = ""
    elif username == "" or password == "" or database.checkCredentials(username, password) == False:
        html_content_to_send = bad_creds_page % submit_hostport
        headers_to_send = ""
    else:
        html_content_to_send = (success_page % submit_hostport) + database.getSecret(username)
        while True:
            rand_val = int(rand_val)
            rand_val = random.getrandbits(64)
            rand_val = str(rand_val)
            print(rand_val)
            if databaseCookies.get(rand_val) == None:
                break
        databaseCookies[rand_val] = username
        print(databaseCookies)
        headers_to_send = "Set-Cookie: token=" + str(rand_val) + "\r\n"
        

    # You need to set the variables:
    # (1) `html_content_to_send` => add the HTML content you'd
    # like to send to the client.
    # Right now, we just send the default login page.
    #html_content_to_send = login_page % submit_hostport (this line was originally uncommented)
    # But other possibilities exist, including
    # html_content_to_send = (success_page % submit_hostport) + <secret>
    # html_content_to_send = bad_creds_page % submit_hostport
    # html_content_to_send = logout_page % submit_hostport
    
    # (2) `headers_to_send` => add any additional headers
    # you'd like to send the client?
    # Right now, we don't send any extra headers.
    # headers_to_send = '' (was originally uncommented)

    # Construct and send the final response
    response  = 'HTTP/1.1 200 OK\r\n'
    response += headers_to_send
    response += 'Content-Type: text/html\r\n\r\n'
    response += html_content_to_send
    print_value('response', response)    
    client.send(response.encode())
    client.close()
    
    print("Served one request/connection!")
    print()

# We will never actually get here.
# Close the listening socket
sock.close()

