"""
CIS 433: Computer Network and Security
Project: Cryptocurrency Mining Models
Authors: Danny Lu, Syd Lynch, Charlie Plachno

Description: The file contains code for the server to distribute work over a network
of machines. The server dynamically allocates work to clients based off of it's hashes
per second. At first all, clients get the same work. Once the client responds to the server
letting it know how fast it can compute hashes.

	Example:
		Let there be two clients, C1 with 100,000 hps, and C2 with 400,000 hps(hps = hashes per second).
		Let initial_work = 10,000

	Server:
		Takes the client's hps and computes (hps/initial_work)*initial_work

		C1 = 100,000/10,000 = 10*10,000 = 100,000
		C2 = 400,000/10,000 = 40*10,000 = 400,000

		Thus our server tailors every work range to meet the needs of every machine.
"""
import socket
import sys
import threading
import os
import math
from random import choice
from string import ascii_letters
from timeit import default_timer as timer


global cond_var
global curr_count
global base
global connections
global initial_work
global target

curr_count = -1
#True = locked, False = unlocked
cond_var = False
connections = {}

#Send a range of work to clients
#Example of range: "1-1000"(Add each number in this range at the end of the base string
#to compute a new hash, keep doing this until the desired hash is found.)
def send_work(conn, addr):
	global curr_count
	global base
	global cond_var
	global connections
	global initial_work
	global target

	initial_work = 1000000
	hps = initial_work
	start = timer()
	duration = 0
	while True:
		duration = timer() - start
		if (cond_var == False):
			cond_var = True
			message = str(curr_count + 1) + '-' + str(curr_count + math.floor((hps/initial_work)*initial_work)) + '-' + target + '-' + base
			#Dymanically allocate a range to clients to compute hashes.
			#Take the client's hashes per second and start sending work
			#to accomidate for slower/faster machines.
			curr_count += math.floor((hps/initial_work)*initial_work)
			print(curr_count)

			print("sent:", message)
			conn.send(message.encode('utf-8'))
			cond_var = False

			#Wait for the client to compute the work and respond with
			#the findings of the specified range
			client_in = str(conn.recv(1024))
			print("received:", client_in, "from:", addr)

			if client_in[2:6] != "done":
				print(">>>" + client_in.split(" ")[0])
				break
			else:
				hps = float(client_in.split(" ")[1][0:-2])
				connections[addr[0]] = hps

	return 0

#Wait for connections, for each new client the server creates a thread
#to communicate with the client.
def main():
	global connections
	global target
	global base

	soc = socket.socket()
	host = "0.0.0.0"
	port = 6500
	soc.bind((host,port))

	thread_list = []
	soc.listen()
	base = str(input("Enter a base string: "))
	target = str(input("Enter a target(number of zeros at the beginning of the hash): "))
	input("Press enter to distribute work to all connected clients.")
	while True:
		connection, address = soc.accept()

		print(address, "connected to server")

		thread = threading.Thread(target = send_work, args = (connection, address))
		thread_list.append(thread)
		thread.start()

main()
