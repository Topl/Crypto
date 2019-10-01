import json
import matplotlib.pyplot as plt
from mpl_toolkits import mplot3d
import numpy as np
import os
import glob
from anytree import Node, RenderTree, AsciiStyle, find_by_attr
from anytree.exporter import DotExporter

# dataDir = '/home/aaron/topl/Crypto/data/'
dataDir = '/home/aaron/topl/ssh/delaySweep1/'

list_of_files = glob.glob(dataDir+'*.tree') # * means all if need specific format then *.csv
#list_of_files = glob.glob('/home/aaron/topl/ssh/delaySweep1/*.tree') # * means all if need specific format then *.csv

xaxis = np.empty([len(list_of_files)])
yaxis = np.empty([len(list_of_files)])
zaxis = np.empty([len(list_of_files)])
taxis = np.empty([len(list_of_files)])
baxis = np.empty([len(list_of_files)])
tines = np.empty([len(list_of_files)])
avgLenTines = np.empty([len(list_of_files)])
print('Total files '+str(len(list_of_files)))
i = 0
for file in list_of_files:
	print('Working on '+str(i))
	f = open(file)
	tree = json.load(f)
	f.close
	ii = 0
	j = 0
	jj = 0
	jjj = 0
	k = 1
	for s in tree["data"]:
		if s["history"][0]["id"] != "":
			j = j + 1
		l = len(s["history"])
		if l < k:
			jj = jj + 1
		k = l
		ll = len(s["blocks"])
		jjj = jjj + ll
		for b in s["blocks"]:
			if ii == 0:
				root = Node(b["id"])
			else:
				Node(b["id"],parent = find_by_attr(root,b["pid"]))
		ii = ii + 1
	zaxis[i] = j
	taxis[i] = jj
	baxis[i] = jjj
	xaxis[i] = float(tree["info"]["delay_ms_km"])
	yaxis[i] = float(tree["info"]["f_s"])
	leaves = root.leaves
	tines[i] = len(leaves)
	avgLen = 0.0
	for lNode in leaves:
		lll = 1
		node = lNode
		while len(node.siblings) == 0:
			node = node.parent
			lll = lll + 1
		avgLen = avgLen + lll
	avgLenTines[i] = avgLen/tines[i]
	#DotExporter(root).to_picture(dataDir+"root_"+str(i)+".png")
	i = i + 1

plt.figure(1)
ax = plt.axes(projection='3d')
ax.scatter3D(xaxis,yaxis,zaxis, c=zaxis, cmap='hsv')
ax.set_xlabel('Delay (ms/km)')
ax.set_ylabel('Active Slot Coefficient')
ax.set_zlabel('Block Number')
ax.set_title('Total blocks on chain after 1000 slots')
plt.show()

plt.figure(2)
ax = plt.axes(projection='3d')
ax.scatter3D(xaxis,yaxis,taxis, c=taxis, cmap='hsv')
ax.set_xlabel('Delay (ms/km)')
ax.set_ylabel('Active Slot Coefficient')
ax.set_zlabel('Number of Reorgs')
ax.set_title('Total Reorgs after 1000 slots')
plt.show()

plt.figure(3)
ax = plt.axes(projection='3d')
ax.scatter3D(xaxis,yaxis,tines, c=tines, cmap='hsv')
ax.set_xlabel('Delay (ms/km)')
ax.set_ylabel('Active Slot Coefficient')
ax.set_zlabel('Number of Tines')
ax.set_title('Total Tines after 1000 slots')
plt.show()

plt.figure(4)
ax = plt.axes(projection='3d')
ax.scatter3D(xaxis,yaxis,avgLenTines, c=avgLenTines, cmap='hsv')
ax.set_xlabel('Delay (ms/km)')
ax.set_ylabel('Active Slot Coefficient')
ax.set_zlabel('Length of Tines')
ax.set_title('Average length of tines after 1000 slots')
plt.show()