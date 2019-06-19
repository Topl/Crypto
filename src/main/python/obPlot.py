import matplotlib.pyplot as plt
import glob
import os
import numpy as np
import matplotlib.cm as cm


list_of_files = glob.glob('/tmp/scorex/test-data/crypto/*.txt') # * means all if need specific format then *.csv
latest_file = max(list_of_files, key=os.path.getctime)

data_file = file(latest_file,'r')


def getColumns(inFile, delim="\t", header=True):
    """
    Get columns of data from inFile. The order of the rows is respected
    
    :param inFile: column file separated by delim
    :param header: if True the first line will be considered a header line
    :returns: a tuple of 2 dicts (cols, indexToName). cols dict has keys that 
    are headings in the inFile, and values are a list of all the entries in that
    column. indexToName dict maps column index to names that are used as keys in 
    the cols dict. The names are the same as the headings used in inFile. If
    header is False, then column indices (starting from 0) are used for the 
    heading names (i.e. the keys in the cols dict)
    """
    cols = {}
    indexToName = {}
    for lineNum, line in enumerate(inFile):
        if lineNum == 0:
            headings = line.split(delim)
            i = 0
            for heading in headings:
                heading = heading.strip()
                if header:
                    cols[heading] = []
                    indexToName[i] = heading
                else:
                    # in this case the heading is actually just a cell
                    cols[i] = [heading]
                    indexToName[i] = i
                i += 1
        else:
            cells = line.split(delim)
            i = 0
            for cell in cells:
                cell = cell.strip()
                cols[indexToName[i]] += [cell]
                i += 1
                
    return cols, indexToName

cols, indexToName = getColumns(data_file," ",True)
data_file.close()


numHolders = int(max(cols[indexToName[0]]))+1
print("Number of holders:")
print(numHolders)
numDataPoints = len(cols[indexToName[0]])
print("Number of data points:")
print(numDataPoints)

colors = cm.rainbow(np.linspace(0, 1, numHolders))

rows = range(numDataPoints)

plt.figure(1)
for row in rows:
	plt.scatter(int(cols["t"][row]),int(cols["blocks_forged"][row]),color=colors[int(cols["Holder_number"][row])],marker =".")
	if int(cols["Holder_number"][row]) == 0 :
		plt.scatter(int(cols["t"][row]),int(cols["t"][row]),color="grey",marker =".")
		plt.scatter(int(cols["t"][row]),int(cols["chain_length"][row]),color="black",marker =".")
plt.ylabel("number of blocks")
plt.xlabel("slot")
plt.title("Blocks forged")
plt.autoscale(enable=True, axis='x', tight=True)
plt.autoscale(enable=True, axis='y', tight=True)
plt.tight_layout()

plt.figure(2)
for row in rows:
	plt.scatter(int(cols["t"][row]),float(cols["alpha"][row]),color=colors[int(cols["Holder_number"][row])],marker =".")
plt.ylabel("alpha")
plt.xlabel("slot")
plt.title("Relative Stake")
plt.autoscale(enable=True, axis='x', tight=True)
plt.autoscale(enable=True, axis='y', tight=True)
plt.tight_layout()



plt.show()



