import dns.query
import dns.message
from datetime import datetime
# Input data
input = input()
print("enter URL: ", input)

# Get top level domain
message = dns.message.make_query(input, dns.rdatatype.A)
response = dns.query.tcp(message, '198.41.0.4')

#print(response)
dict = {}
dict2 = {}
time = 0
TIMES_FOR_GRAPHS = []

#resolve is a recursive function which loops through each address it finds in additional and authority,
#Adds them to a dictionary (as to not check the same IP multiple times) and if it finds any 
#answer, adds that to a seperate dictionary for the same reason.
#When complete, all answers should be in dict2
def resolve(response):
    global time
    if(len(response.answer) == 0):
        for server in response.additional:
            Ip = server.__getitem__(0)
            try:
                if(Ip not in dict):
                    response = dns.query.udp(message, str(Ip))
                    dict[Ip] = response
                    resolve(response)
                    time += response.time

                for auth in response.authority:
                    name = auth.__getitem__(0)
                    if(name not in dict):
                        message2 = dns.message.make_query(str(name), dns.rdatatype.A)
                        response = dns.query.udp(message2, str(Ip))
                        dict[name] = response
                        resolve(response)
                        time += response.time
            except:
                pass
        
    else: #Answer found. Add it to dictionary
        dict2[response.answer.__getitem__(0)[0].address] = 0

# loop through to find ANS
resolve(response)

#Print all data
keys = str(dict2.keys())[10:-1]
print("QUESTION SECTION:")
print(input, "    IN A")
print("ANSWER SECTION:")
print(input, "    ", "IN A", keys)
print("QUERY TIME: ",time, "s")
TIMES_FOR_GRAPHS.append(time)
print("WHEN: ", datetime.datetime.now())
