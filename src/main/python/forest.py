import json
import matplotlib.pyplot as plt
import numpy as np
import os
import glob

list_of_files = glob.glob('/home/aaron/topl/Crypto/data/*.tree') # * means all if need specific format then *.csv

data = np.empty([])
allIds = []
i = 0
for file in list_of_files:
	f = open(file)
	tree = json.load(f)
	f.close
	datum = np.empty([len(tree)],dtype='object')
	j = 0
	for s in tree:
		datum[j] = s['history'][0]['id']
		j = j + 1
	if i == 0:
		data = np.empty([len(list_of_files),j],dtype='object')
		allIds = [set() for _ in range(j)]
	j = 0
	for s in tree:
		for b in s['blocks']:
			allIds[j].add(b['id'])
		j = j + 1
	data[i] = datum
	i = i + 1
	
numTrees = np.shape(data)[0]
numSlots = np.shape(data)[1]

for j in range(0,numSlots):
	setOfIds = set([])
	for i in range(0,numTrees):
		setOfIds.add(data[i][j])
	if setOfIds == set(['']):
		print(j,len(allIds[j]),"empty")
	else:
		print(j,len(allIds[j]),len(setOfIds))



