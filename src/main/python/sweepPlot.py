import json
import matplotlib.pyplot as plt
from mpl_toolkits import mplot3d
import numpy as np
import os
import glob
from anytree import Node, RenderTree, AsciiStyle, find_by_attr, PreOrderIter
from anytree.exporter import UniqueDotExporter
import uuid

dataDir = '/tmp/scorex/test-data/crypto/'
printGraphs = True

list_of_files = glob.glob(dataDir+'*.tree') # * means all if need specific format then *.csv

xaxis = np.empty([len(list_of_files)])
yaxis = np.empty([len(list_of_files)])
zaxis = np.empty([len(list_of_files)])
taxis = np.empty([len(list_of_files)])
baxis = np.empty([len(list_of_files)])
tines = np.empty([len(list_of_files)])
avgLenTines = np.empty([len(list_of_files)])
avgLenTinesS = np.empty([len(list_of_files)])

def edgetypefunc(node, child):
	return '--'

def nodeattrfunc(node):
	out = 'label=\"'+node.name+'\"'
	if node.name == "":
		out = out+',shape=circle'
	else:
		out = out+',shape=box'
	if node.highlight == 1:
		out = out+',style=filled,fillcolor=cyan'
	if node.highlight == 2:
		out = out+',style=filled,fillcolor=pink'
	if node.highlight == 3:
		out = out+',style=filled,fillcolor=red'
	return out

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
	prevSlotNodes = []
	thisSlotNodes = []
	for s in tree["data"]:
		if s["history"][0]["id"] != "":
			j = j + 1
			lastId = s["history"][0]["id"]
		l = len(s["history"])
		if l < k:
			jj = jj + 1
		k = l
		ll = len(s["blocks"])
		jjj = jjj + ll
		for b in s["blocks"]:
			if ii == 0:
				root = Node(b["id"],highlight=1,slot=int(b["bs"]))
				prevSlotNodes = [root]
			else:
				sdiff = int(b["bs"]) - int(b["ps"])
				oldName = ""
				highlightNumber = 0
				if 'adversarial:true' in b["info"]:
					highlightNumber = 2
				else:
					highlightNumber = 0
				if sdiff == 1 or not printGraphs:
					Node(b["id"],parent = find_by_attr(root,b["pid"]),highlight=highlightNumber,slot=int(b["bs"]))
				else:
					emptySlotNum = int(b["ps"])
					while sdiff > 1:
						emptySlotNum = emptySlotNum + 1
						if oldName == "":
							newName = 'empty:'+uuid.uuid4().hex
							Node(newName,parent = find_by_attr(root,b["pid"]),highlight=highlightNumber,slot=emptySlotNum)
							oldName = newName
						else:
							newName = 'empty:'+uuid.uuid4().hex
							Node(newName,parent = find_by_attr(root,oldName),highlight=highlightNumber,slot=emptySlotNum)
							oldName = newName
						sdiff = sdiff - 1
					Node(b["id"],parent = find_by_attr(root,oldName),highlight=highlightNumber,slot=int(b["bs"]))
		ii = ii + 1
	zaxis[i] = j
	taxis[i] = jj
	baxis[i] = jjj
	xaxis[i] = float(tree["info"]["delay_ms_km"])
	yaxis[i] = float(tree["info"]["f_s"])
	leaves = root.leaves
	tines[i] = len(leaves)
	avgLen = 0.0
	avgLenS = 0.0
	if printGraphs:
		node = find_by_attr(root,lastId)
		while not node.is_root:
			if node.highlight == 2:
				node.highlight = 3
			if node.highlight == 0:
				node.highlight = 1
			node=node.parent
		for node in PreOrderIter(root):
			nodeName = node.name
			if 'empty' in nodeName:
				node.name = ""
			else:
				node.name = nodeName[0:3]
		dots = UniqueDotExporter(root,graph='graph',nodeattrfunc=nodeattrfunc,edgetypefunc=edgetypefunc)
		dots.to_picture(dataDir+"root_"+str(i)+".png")
	if len(leaves) == 1:
		avgLen = root.height
		avgLenS = leaves[0].slot
	else:
		for lNode in leaves:
			lll = 1
			lllS = 1
			node = lNode
			while len(node.siblings) == 0:
				lllS = lllS + node.slot - node.parent.slot
				node = node.parent
				lll = lll + 1
			avgLen = avgLen + lll
			avgLenS = avgLen + lllS
	avgLenTines[i] = avgLen/tines[i]
	avgLenTinesS[i] = avgLenS/tines[i]
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
ax.set_zlabel('Length of Tines (Block Number)')
ax.set_title('Average length of tines after 1000 slots')
plt.show()

plt.figure(5)
ax = plt.axes(projection='3d')
ax.scatter3D(xaxis,yaxis,avgLenTinesS, c=avgLenTinesS, cmap='hsv')
ax.set_xlabel('Delay (ms/km)')
ax.set_ylabel('Active Slot Coefficient')
ax.set_zlabel('Length of Tines (Slot Number)')
ax.set_title('Average length of tines after 1000 slots')
plt.show()