# Crypto Election

Crypto Election is a localhost playground for voting and following along with Diffie-Hellman Key Exchange, RSA (for
signing), and AES (in CBC mode).

## Installation

It is strongly recommended to use a virtual environment as the pycryptodome library has name conflicts with crypto and
pycrypto libraries. Start by cloning the repo and cd into the main directory:

```bash
git clone https://github.com/gabeorosan/cryptoElection.git
cd cryptoElection/
```

Then make a virtual environment and activate it

```bash
python -m venv myenv
source myenv/bin/activate
```

Download the requirements with pip

```
pip install -r requirements.txt
```

Finally, you can use the start scripts to run it. There are two scripts, start.sh for starting the servers and sim.sh
for crawling the web forms and simulating a simple election. To use a script, first make it an executable, then run it

```
chmod +x start.sh
./start.sh
```

If you just want to simulate the election, simply do the same thing for the sim script in a new tab (you will need to
activate the virtual environment again), then go to [localhost:4000/](http://localhost:4000/) to view the results. Note
that the script is making requests to each webpage, submitting the forms, and getting the responses/public info for each
form for 5 voters so it may take 10-15 seconds. From there, you can also navigate to the CLA and Cipher helper pages from the navbar. Additionally, you can add voters and
adjust other parameters for the simulation in the scrape/spiders/votespiders.py file.

If you want to go through the voting process yourself, this is the process:

1. Navigate to the Central Legitimization Agency (CLA) page at [localhost:3000/](http://localhost:3000/). Note that
there is a default time for the election of 5 minutes, so the clock is ticking! Just kidding, you can change the
election time at the top of the CLA.py file if you want more time. On the CLA page, you can create a citizen by entering a name
and clicking create. Whenever you submit a form, there should be response text that pops up that you will want to copy. In this case, this contains
the ID number for the citizen you made (like an SSN).

2. Open a different tab to the Cipher Helper (CH) page at [localhost:5000/](http://localhost:5000/). This is where you will be able to encrypt and
decrypt messages. Start by pasting your ID into the message input, and get the public exponent A from the CLA page for
the other input (the public info you need to copy is highlighted in green). Click encrypt, and copy the response
(easiest way is just to click on the far left of it and drag down).

3. Input your encrypted id and the other required information from the CH page into the register form on the CLA page
and click register. Take the encrypted response, and the other required information from the CLA page and paste it into
the decryption form on the CH page. Decrypt the message - this is your validation number (VN).

4. Now you will want to encrypt your VN to send it to the Central Tabulating Facility (CTF) at
[localhost:4000](http://localhost:4000/). This is the same process as before, but this time you will need the public info from
the CTF page to fill out the encryption form. Encrypt your VN and copy the response.

5. Finally, go to the CTF page and fill out the vote form with your VN and info from your Cipher Helper page, along with the candidate you wish to vote for (there is
no designated list, any new candidates will simply be added to the list of candidates when the vote is processed). You
should see your vote pop up (as long as you completed the process in time) and the candidate you voted for getting a
tally.

The election will automatically end when time runs out, but if you want to see the results right away you can run the
vote script from the main folder (which you should still be in if you didn't navigate to any files), which simulates 5
votes and automatically ends the election afterwards.

```
scrapy crawl votespider
```

The results are displayed on the CTF page. If you want to run another election, you can re-initialize the CLA by
clicking the first button on that page, which automatically starts a new election and clears the votes & candidates from
the CTF page. 

## License
[MIT](https://choosealicense.com/licenses/mit/)

