import requests
#try: input = input()
#except NameError: pass

# Global values
base = "http://crypto.praetorian.com/{}"
email = input("Enter your email address: ")
auth_token = None

# Used for authentication
def token(email):
	global auth_token
	if not auth_token:
		url = base.format("api-token-auth/")
		resp = requests.post(url, data={"email":email})
		auth_token = {"Authorization":"JWT " + resp.json()['token']}
		resp.close()
	return auth_token

# Fetch the challenge and hint for level n
def fetch(n):
	url = base.format("challenge/{}/".format(n))
	resp = requests.get(url, headers=token(email))
	resp.close()
	if resp.status_code != 200:
		raise Exception(resp.json()['detail'])
	return resp.json()

# Submit a guess for level n
def solve(n, guess):
	url = base.format("challenge/{}/".format(n))
	data = {"guess": guess}
	resp = requests.post(url, headers=token(email), data=data)
	resp.close()
	if resp.status_code != 200:
		raise Exception(resp.json()['detail'])
	return resp.json()


# Fetch level 0
level = 2
hashes = {}
data = fetch(level)
print(data)

##################Solved Here##################
def answer():
	cipherText, plaintext, key = data['challenge'], "", 23
	for ch in cipherText:
		if ch.isalpha():
			if ch.isupper():
				plaintext += chr((((ord(ch) - 65) - key) % 26) + 65)
			if ch.islower():
				plaintext += chr((((ord(ch) - 97) - key) % 26) + 97)
		else:
			plaintext += ch
	
	return plaintext
##################Solved Here##################

guess = answer()
h = solve(level, guess)

# If we obtained a hash add it to the dict
if 'hash' in h: hashes[level] = h['hash']


# Display all current hash
for k,v in hashes.items():
	print("Level {}: {}".format(k, v))
