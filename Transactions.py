#Transaction.py
import Signatures
#Signatures.sign
#Signatures.verify

class Tx:
    inputs = None
    sigs = None
    reqd = None
    def __init__(self):
        self.inputs = []
        self.sigs = []
        self.reqd = []
    def add_input(self, from_addr, dataPayload):
        self.inputs.append((from_addr, dataPayload))
    def add_reqd(self, addr):
        self.reqd.append(addr)
    def sign(self, private):
        message = self.__gather()
        newsig = Signatures.sign(message, private)
        self.sigs.append(newsig)        
    def is_valid(self):
        total_in = 0
        #total_out = 0
        message = self.__gather()
        for addr,amount in self.inputs:
            found = False
            for s in self.sigs:
                if Signatures.verify(message, s, addr) :
                    print ("Signature is valid!")
                    found = True
            if not found:
                print ("No good sig found for " + str(message))
                return False
        for addr in self.reqd:
            found = False
            for s in self.sigs:
                if Signatures.verify(message, s, addr) :
                    print ("Signature is not valid in reqd!")
                    found = True
            if not found:
                print ("reqd NotFound!")
                return False

        print("returned true")
        return True
    def __gather(self):
        data=[]
        data.append(self.inputs)
        data.append(self.reqd)
        return data
    def __repr__(self):
        reprstr = "INPUTS:\n"
        for addr, amt in self.inputs:
            reprstr = reprstr + str(amt) + " from " + str(addr) + "\n"

        reprstr = reprstr + "REQD:\n"
        for r in self.reqd:
            reprstr = reprstr + str(r) + "\n"
            
        reprstr = reprstr + "SIGS:\n"
        for s in self.sigs:
            reprstr = reprstr + str(s) + "\n"
        reprstr = reprstr + "END\n"
        return reprstr
        
        

if __name__ == "__main__":
    pr1, pu1 = Signatures.generate_keys()
    pr2, pu2 = Signatures.generate_keys()
    pr3, pu3 = Signatures.generate_keys()
    pr4, pu4 = Signatures.generate_keys()

    Tx1 = Tx()
    Tx1.add_input(pu1, 1)
    Tx1.sign(pr1)

    Tx2 = Tx()
    Tx2.add_input(pu1, 2)
    Tx2.sign(pr1)

    Tx3 = Tx()
    Tx3.add_input(pu3, 1.2)
    Tx3.add_reqd(pu4)
    Tx3.sign(pr3)
    Tx3.sign(pr4)

    Tx4 = Tx()
    Tx4.add_input(pu1, 1)
    Tx4.sign(pr2)

    Tx5 = Tx()
    Tx5.add_input(pu3, 1.2)
    Tx5.add_reqd(pu4)
    Tx5.sign(pr3)
  
    for t in [Tx1, Tx2, Tx3, Tx4, Tx5]:
        print("Checking .........")
        if t.is_valid():
            print("Success! Tx is valid")
        else:
            print("ERROR! Tx is invalid")
        print("Ended ............")
            
    
        




    
    
        
