import json
import matplotlib.pyplot as plt
from mpl_toolkits import mplot3d
import numpy as np
import os
import glob
from anytree import Node, RenderTree, AsciiStyle, find_by_attr

list_of_files = glob.glob('/home/aaron/topl/ssh/delaySweep1/*.tree') # * means all if need specific format then *.csv

xaxis = np.empty([len(list_of_files)])
yaxis = np.empty([len(list_of_files)])
zaxis = np.empty([len(list_of_files)])
taxis = np.empty([len(list_of_files)])
baxis = np.empty([len(list_of_files)])
tines = np.empty([len(list_of_files)])
print(len(list_of_files))
i = 0
for file in list_of_files:
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
		if i == 100:
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
ax.set_zlabel('Number of Tines')
ax.set_title('Total reorgs after 1000 slots')
plt.show()

plt.figure(3)
ax = plt.axes(projection='3d')
ax.scatter3D(xaxis,yaxis,baxis, c=baxis, cmap='hsv')
ax.set_xlabel('Delay (ms/km)')
ax.set_ylabel('Active Slot Coefficient')
ax.set_zlabel('Number of Blocks')
ax.set_title('Total blocks after 1000 slots')
plt.show()