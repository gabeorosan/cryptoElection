import datetime
from datetime import timedelta
d1 = datetime.datetime.now()
d2 = d1 + timedelta(minutes=5)
print(d1)
print(d2)
d3 = d2 - d1
print(d3.seconds)
print(d3.seconds > 0)
s = str(d1)
sec =d3.seconds
p = str(sec//60) + ':' + str(float(sec%60))
o = datetime.datetime.strptime(p, "%M:%S.%f")
print(o)
