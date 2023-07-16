# NetFS 1 (misc)
Writeup by: [xlr8or](https://ctftime.org/team/235001)

As part of this challenge we get access to a server (and its source code) written in Python.
The purpose of this server is for the user to be able to read files on the system.
Our goal is to read the file in `secret/flag.txt`, however before we can read files we must authenticate.

The system contains 2 users:
```python
assert os.path.isfile("secret/password.txt"), "Password file not found."

MAX_SIZE = 0x1000
LOGIN_USERS = {
    b'guest': b'guest',
    b'admin': open("secret/password.txt", "rb").read().strip()
}
PROTECTED = [b"server.py", b"secret"]

assert re.fullmatch(b"[0-9a-f]+", LOGIN_USERS[b'admin'])
```

The password of the *guest* user is known, however the password of *admin* is unknown to us, other than the fact that it only consists of digits and letters `a` thorough `f`.
Our goal is to authenticate with admin, since authenticating with guest, makes the user unable to access any files path, that contains any element of `PROTECTED`:

```python
# Check filepath
if not self.is_admin and \
   any(map(lambda name: name in filepath, PROTECTED)):
    self.response(b"Permission denied.\n")
    continue
```

So let's take a closer look at the authentication method:
```python
    def authenticate(self):
        """Login prompt"""
        username = password = b''
        with Timeout(30):
            # Receive username
            self.response(b"Username: ")
            username = self.recvline()
            if username is None: return

            if username in LOGIN_USERS:
                password = LOGIN_USERS[username]
            else:
                self.response(b"No such a user exists.\n")
                return

        with Timeout(30):
            # Receive password
            self.response(b"Password: ")
            i = 0
            while i < len(password):
                c = self._conn.recv(1)
                if c == b'':
                    return
                elif c != password[i:i+1]:
                    self.response(b"Incorrect password.\n")
                    return
                i += 1

            if self._conn.recv(1) != b'\n':
                self.response(b"Incorrect password.\n")
                return

        self.response(b"Logged in.\n")
        self._auth = True
        self._user = username
```

First, the system reads our username, and ensures, that it is known in the system.
Afterwards we continue with checking the password, however there's a flaw here, that allows us to guess the password one character at a time.
The password is received by the server one character at a time, and if that given character doesn't match the password, then we get notified that the password is incorrect.
However if the character we sent is correct, then the server will wait for the next character.

This means that we can try all 16 possibilities for a given position, and the attempt, which doesn't generate an *Incorrect password.* response gets appended to the overall password we have so far.

Using `solve.py` we can bruteforce the password, and use it to authenticate as `admin` and read the flag file.
