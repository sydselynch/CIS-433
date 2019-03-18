"""
CIS 433: Computer Network and Security
Project: Cryptocurrency Mining Models
Authors: Danny Lu, Syd Lynch, Charlie Plachno

Description: This file contains the code for computing hashes on a 
mobile device. It doesn't connect to the server and receives work because
we had issues with the firewall that we couldn't resolve in time. However,
it does allow us to see how fast mobile processors are at computing
hashes.

    Example:
        Let our base string be "Hello World" and our range be 1-1000

    Compute:
        Hash -> "Hello World1"
        Hash -> "Hello World2"
        ...
        Hash -> "Hello World1000"

    Check the hash if there is a number of zeros at the beginning of the hash that equals
    the number of the specified target.

    Example:
        Let our target be 5

        Correct Hash -> "000003j60sh38ylemis0383743j3i38"
        Incorrect Hash -> "2j28dk09es7f9fj0gg9f8df0f0g9g0f"

"""
import hashlib
import sys

#Used to compute hashes and calls check_hash to see if the hash is the one we want
def proof_of_work(source, dest, target, base_str):
    #used to add to the end of the string to compute a different hash
    counter = source
    #stiring for hashing
    string = base_str
    work = str(hashlib.sha256(string.encode("utf-8")).hexdigest())
    while(check_hash(work,target) == False):
        if counter == dest:
            return "done"
        counter += 1
        work = str(hashlib.sha256((string+str(counter)).encode("utf-8")).hexdigest())
        #prints all the predicted hashes
        #print(work)

    #prints the counter and how many iterations to get to the desired hash
    return ("found:" + str(counter))

#Check if there are zeros equal to the number of the target at the beginning of the hash
def check_hash(hashcode, target):
    zeros = 0
    check_index = 0
    for index in range(len(hashcode)):
        if (hashcode[index] == "0") and (index == check_index):
            zeros += 1
            check_index += 1
        elif (zeros == target):
            return True
        else:
            return False
    return False

#When receiving work from the server the message is in a specific format
#Message Example: "100-1000-6-Hello World"
def decodeMess(message):
    split_mess = message.split('-')
    start_hash = int(split_mess[0])
    end_hash = int(split_mess[1])
    target = int(split_mess[2])
    base_str = split_mess[3]

    return start_hash, end_hash, target, base_str


global cond_var
global curr_count
global base

curr_count = -1
base = "H"
#True = locked, False = unlocked
cond_var = False


def main():
    global cond_var
    global curr_count
    global base
    while True:
        message = str(curr_count + 1) + '-' + str(curr_count + 100000) + '-' + '6' + '-' + base
        curr_count += 100000

        start, end, tar, base = decodeMess(message)

        answer = proof_of_work(start, end, tar, base)
        if answer == "done":
            print("Didn't get the hash")
        else:
            print(answer)
            break

        answer = answer.encode('utf-8')

main()
