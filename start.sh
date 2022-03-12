#! /bin/bash

(trap 'kill 0' SIGINT EXIT; python cla/cla.py & python ctf/ctf.py & python ch/ch.py)
