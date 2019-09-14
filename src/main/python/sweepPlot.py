import json
import matplotlib.pyplot as plt
from mpl_toolkits import mplot3d
import numpy as np
import os
import glob

list_of_files = glob.glob('/home/aaron/topl/Crypto/target/universal/stage/bin/*.tree') # * means all if need specific format then *.csv

xaxis = np.empty([len(list_of_files)])
yaxis = np.empty([len(list_of_files)])
zaxis = np.empty([len(list_of_files)])

i = 0
for file in list_of_files:
	f = open(file)
	tree = json.load(f)
	f.close
	j = 0
	for s in tree["data"]:
		if s["history"][0]["id"] != "":
			j = j + 1
	zaxis[i] = j
	xaxis[i] = float(tree["info"]["delay_ms_km"])
	yaxis[i] = float(tree["info"]["f_s"])
	i = i + 1
	
ax = plt.axes(projection='3d')
ax.scatter3D(xaxis,yaxis,zaxis, c=zaxis, cmap='hsv')
ax.set_xlabel('Delay (ms/km)')
ax.set_ylabel('Active Slot Coefficient')
ax.set_zlabel('Block Number')
ax.set_title('Total blocks on chain after 200 slots')
plt.show()