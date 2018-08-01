import pdb
import time
class Vehicle(object):
    def __init__(self,name=None):
       if name:
	       self.name = name
       else:
           self.name = "Default"

    def get_name(self):
       print("HI I'm %s"%self.name)

class Car(Vehicle):
     pass

pdb.set_trace()
c = Car("Suzuki")
c.get_name()

time.sleep(45)
