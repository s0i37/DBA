from random import random

print "<script>\r\na={\r\n"
for i in xrange(1 * 1000 * 1000):
	print "{i}: [{a},{b},{c}],\r\n".format( i=i, a=random(), b=random(), c=random() )
print "}\r\n</script>\r\n"