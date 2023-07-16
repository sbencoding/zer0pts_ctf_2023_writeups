# NetFS 2 (misc)
Writeup by: [xlr8or](https://ctftime.org/team/235001)

**Note:** This writeup assumes you are familiar with the solution to the NetFS 1 challenge.

This time we get a very similar server script, but it is slightly updated in the authentication function where the password is checked:
```python
with Timeout(5) as timer:
    # Receive password
    self.response(b"Password: ")
    i = 0
    while i < len(password):
        c = self._conn.recv(1)
        if c == b'':
            timer.wait()
            self.response(b"Incorrect password.\n")
            return
        elif c != password[i:i+1]:
            timer.wait()
            self.response(b"Incorrect password.\n")
            return
        i += 1

    if self._conn.recv(1) != b'\n':
        timer.wait()
        self.response(b"Incorrect password.\n")
        return

self.response(b"Logged in.\n")
self._auth = True
self._user = username
```

The password is still checked one character at a time, however we are not immediately notified when the character is incorrect, rather the timer waits for a similar amount of time, as timing out would, if the single character we sent was correct.

Let's see how the `timer.wait()` function is implemented:
```python
def wait(self):
    signal.alarm(0)
    while time.time() - self.start < self.seconds:
        time.sleep(0.1)
    time.sleep(random.random())
```

Essentially, this will cancel the signal countdown for the alarm signal that was set, when the `Timer` was "entered" in the `with` block.
Then wait for the remaining time, and delay for a random amount of time.

When the execution goes outside the `with` statement the `__exit__` handler gets called:
```python
def __exit__(self, _type, _value, _traceback):
    signal.alarm(0)
    time.sleep(random.random())
```

This will again sleep for a random amount of time.
However, when the password character is correct, we don't call `timer.wait()`, so we have a situation, where an incorrect character would sleep a random amount of time twice (because calling `timer.wait()`), but a correct character would only sleep the random amount of time once.

I spent some time analysing this route, trying to see if I can deduce the correct character from the timings.
Unfortunately I couldn't manage to find a way to deduce the correct character from the timing, in fact all methods I have tried were more likely to report an incorrect character as the best potential guess.

At this point I started inspecting the traffic in Wireshark, as I was trying to see if we can somehow detect, that when the password character is incorrect, the program waits, then exits, and never calls `socket.recv(1)` again.
Although I saw, that all packets are acknowledged, even after sending an incorrect password character, I noticed something interesting.

When sending an incorrect password character, the server would send an `RST` packet, and netcat would display `read(net): Connection reset by peer`, while sending the correct password character, would produce no such message in netcat and network traffic would not contain any `RST` packets.

This is also true for the remote, with a slight change, when the password character is correct, there's an `RST` packet, however it is sent by the client to the server.
More important is that netcat shows the same behavior with regards to the error message on the remote as well.
Using this knowledge, we have an oracle for a single password character at a time again, so we can write a script that can recover the `admin` password.

`solve.py` is going to recover the `admin` password, which can then be used to read the flag file.

The flag hints at using `procfs` as an oracle, so it is possible that there are multiple solutions to this challenge, because indeed, except for the blacklisted words in `PROTECTED` we have arbitrary file read with the `guest` user.
