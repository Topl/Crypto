import glob
import os
import pandas as pd
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt


list_of_files = glob.glob('/tmp/scorex/test-data/crypto/*.graph') # * means all if need specific format then *.csv
latest_file = max(list_of_files, key=os.path.getctime)

data_file = open(latest_file,'r')


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
            if len(cells) == len(headings):
                i = 0
                for cell in cells:
                    cell = cell.strip()
                    cols[indexToName[i]] += [cell]
                    i += 1
    return cols, indexToName

cols, indexToName = getColumns(data_file," ",False)
data_file.close()


numHolders = len(cols[indexToName[0]])
print("Number of holders:")
print(numHolders)

fromList = []
toList = []

for row in range(numHolders):
    for col in range(numHolders):
        entry = int(cols[indexToName[col]][row])
        if entry == 1:
            fromList.append(str(row))
            toList.append(str(col))



# ------- DIRECTED

# Build a dataframe with your connections
# This time a pair can appear 2 times, in one side or in the other!
df = pd.DataFrame({ 'from':fromList, 'to':toList})
df

# Build your graph. Note that we use the DiGraph function to create the graph!
G=nx.from_pandas_edgelist(df, 'from', 'to', create_using=nx.DiGraph() )
nx.spring_layout(G,k=0.5,iterations=50)
# Make the graph
nx.draw(G, with_labels=True, node_size=1000, alpha=0.3, arrows=True, scale = 2)

# Build your graph
plt.show()



