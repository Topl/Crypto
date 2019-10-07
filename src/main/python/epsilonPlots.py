import numpy as np
import matplotlib
from matplotlib import rcParams, cycler
matplotlib.rcParams['text.usetex'] = True
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.font_manager import FontProperties

epsilon = np.linspace(0.0,1.0,100)

N = 12
# O_f = 1-np.exp(1.0/(1.0+delta))*(1/2+epsilon/2)
# Omega_k = 192*delta/epsilon
# Omega_s = Omega_k*0.25/O_f
# Omega_R = 6.0*Omega_s

def O_f(delta):
	out = np.empty(len(epsilon))
	i = 0
	for e in epsilon:
		v = 1-np.exp(1.0/(1.0+delta))*(1/2+e/2)
		if v > 0.0:
			out[i] = v
		else:
			out[i] = None
		i = i + 1
	return out

data00 = [ O_f(delta) for delta in range(N) ]

print(len(data00[1]))

data01 = [ 192*delta/epsilon for delta in range(N) ]

print(len(data01[1]))

data10 = [ data01[delta]*0.25/data00[delta] for delta in range(N) ]

print(len(data10[1]))

data11 = [6.0*data10[delta] for delta in range(N)]

print(len(data11[1]))

data00 = np.array(data00).T
data01 = np.array(data01).T
data10 = np.array(data10).T
data11 = np.array(data11).T

cmap = plt.cm.coolwarm
rcParams['axes.prop_cycle'] = cycler(color=cmap(np.linspace(0, 1, N)))

fig, ax = plt.subplots(2,2)
custom_lines = [Line2D([0], [0], color=cmap(0.), lw=4),
                Line2D([0], [0], color=cmap(.5), lw=4),
                Line2D([0], [0], color=cmap(1.), lw=4)]
ax[0,0].plot(epsilon,data00)
ax[0,0].set_xlabel('$\epsilon$')
ax[0,0].set_ylabel('$O(f)$')
ax[0,1].plot(epsilon,data01)
ax[0,1].set_xlabel('$\epsilon$')
ax[0,1].set_ylabel('$\Omega(k)$')
ax[1,0].plot(epsilon,data10)
ax[1,0].set_xlabel('$\epsilon$')
ax[1,0].set_ylabel('$\Omega(s)$')
ax[1,1].plot(epsilon,data11)
ax[1,1].set_xlabel('$\epsilon$')
ax[1,1].set_ylabel('$\Omega(R)$')

fontP = FontProperties()
fontP.set_size('large')

fig.legend(custom_lines, ['$\Delta = 0$', '$\Delta = '+str(int(N/2))+'$', '$\Delta = '+str(N)+'$'],prop=fontP)
fig.suptitle('Upper and lower bounds set by $(1-f)^{\Delta+1} \ge (1+\epsilon)/2$')
plt.show()