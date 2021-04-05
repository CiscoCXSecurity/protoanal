# protoanal.py - unknown network protocol analysis toolkit
#
# Copyright:
#  Tim Varkalis (tim.analyst@gmail.com) - monkeynut.eu
#  Security Consultant - Portcullis Computer Security Limited.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

#from scapy.all import *
from scapy.utils import rdpcap
from scapy.plist import PacketList
from scapy.layers.inet import UDP, Raw
from subprocess import Popen
import numpy as np
import scipy.stats as ss
import pylab as pl
import networkx as nx
import itertools as it
import pygraphviz as gv

class Conversation(object):
	def __init__( self, packets , localport = 50002, remoteport = 4172, isUDP = True ):
		'''
		Initialise a conversation from a pcap file or a list otherwise obtained from scapy 
		using scapy.rdpcap (also available as udpanal.rdpcap).
		
		Args:
		* packets - either string representing relative or absolute filename for pcap file
					or PacketList object returned by rdpcap
		* localport - the UDP port you communicated from
		* remoteport - the UDP port you are communicating with
		* isUDP - for future use when TCP & SCTP are also implemented
		'''
		if type(packets) == type(''):
			pktlist = rdpcap( packets )
		elif type(PacketList()) == type( packets ):
			pktlist = packets # re-initialise, take the penalty to kill that annoying 'filter multiplicity)
		else:
			self = packets
		
		self.lport = localport
		self.rport = remoteport
		
		if isUDP: 
			pktlist = pktlist.filter( lambda x: x.haslayer(UDP) )
			pktlist = pktlist.filter( lambda x: 
				x.getlayer(UDP).dport == self.lport or
				x.getlayer(UDP).sport == self.lport or
				x.getlayer(UDP).dport == self.rport or
				x.getlayer(UDP).sport == self.rport	)
			self.pktlist = PacketList(pktlist)
		self.count = len(self.pktlist)
		return
	
	def __getitem__(self, y):
		re

	def fromLocal( self , asConvo = True ):	# asConvo = False just returns packetlist which is more efficient.
		'''
		Returns a conversation object or PacketList containing only packets sent from the local port.
		It optionally takes an argument which if true returns the result as a conversation object or a
		filtered PacketList object (for speed or list customisation before creating conversation).
		'''
		m = self.pktlist.filter( lambda x: x[UDP].sport == self.lport )
		if asConvo:	return Conversation(m)
		else:		return m
	
	def fromRemote( self, asConvo = True ):
		'''
		Works as fromLocal, but packets coming from the remote side.
		'''
		m = self.pktlist.filter( lambda x: x[UDP].sport == self.rport )
		if asConvo:	return Conversation(m)
		else:		return m
	
	def fromEither( self, asConvo = True ):
		'''
		Works as fromLocal, but includes packets originating either local or remotely.
		'''
		m = self.pktlist.filter( lambda x: x[UDP].sport == self.lport or x[UDP].sport == self.rport )
		if asConvo:	return Conversation(m)
		else:		return m
	
	def subrange( self, end, start = 0, asConvo = True ):
		'''
		Select a range of packets by position index.
		'''
		m = self.pktlist[start:end]
		if asConvo:	return Conversation(m)
		else:		return m
	
	def size( self ):
		'''
		Returns the size (in bytes) of each UDP payload in the Conversation as a numpy array.
		'''
		plens = np.array( [ len(c[Raw].load) for c in self.pktlist ] )
		return plens
	
	def sizes( self ):
		'''
		Returns the set of sizes (in bytes) of packet payloads.
		'''
		return set(self.size())
	
	def sizeIs( self, size , asConvo = True):
		'''
		Returns a filtered PacketList object containing only those packets with payloads of the specified size.
		'''
		m = self.pktlist.filter( lambda x: len( x[Raw].load ) == size )
		if asConvo:	return Conversation(m)
		else:		return m
	
	def sizeBelow( self, size , asConvo = True):
		'''
		Returns a filtered PacketList object containing only those packets with payloads smaller than or equal to size
		'''
		m = self.pktlist.filter( lambda x: len( x[Raw].load ) <= size )
		if asConvo:	return Conversation(m)
		else:		return m
	
	def sizeAbove( self, size , asConvo = True):
		'''
		Returns a filtered PacketList object containing only those packets with payloads larger than or equal to the specified number of bytes.
		'''
		m = self.pktlist.filter( lambda x: len( x[Raw].load ) >= size )
		if asConvo:	return Conversation(m)
		else:		return m
	
	def sizeHistogram(self, plot=True):
		'''
		Simplifies the procss of displaying histograms of payload sizes. This is a useful way to classify packets.
		If plot = True, it will display the histogram, else it will return the tuple ( counts, bins ).
		
		If you want finer grained control just import pylab as pl and get cracking!
		'''
		if plot:
			pl.hist( self.size() )
			pl.show()
		else:
			return pl.histogram( self.size() )
		
	def statePlot( self , bucketwidth, offsets, filename = 'state.dot', display=True ):
		'''
		bucketwidth is the number of bytes in each section of the packet. Offset selects which section is of interest.
		The result of this function is a graph where the nodes are packet states and the directed arcs show numbered
		transitions between states.
		
		Beware, if there are a large number of states and indices the graph will likely be indecipherable if it
		even generates. Choose the values wisely.
		
		In future this will be more useful, based on multiple lengths using a scapy dissection definition.
		For now a spec for byte samples and offsets is all you get. Tools will be included to look at bit patterns
		in order to determine the existence and properties of individual flags.  However, at this stage, that should
		be both trivial and irrelevant.'''
		
		statesamples = Samples( self, bucketwidth * ( np.array(offsets).max() +1 ) , bucketwidth )
		valuesetlist = []
		valueslist = []
		for o in offsets:
			valueset = statesamples.asHexSet(o)
			print valueset
			valuesetlist.append( valueset )
			valueslist.append( statesamples.asHex(o) )
			
		nodelist = [ n for n in it.product(*valuesetlist) ]
		G = nx.MultiDiGraph()
		G.add_nodes_from( nodelist )
		for i in range( len( valueslist[0] ) - 1):
			nodetuple = []
			for j in range( len( offsets ) ):
				nodetuple.append( valueslist[j][i] )
			thisnodetuple = tuple( nodetuple )
			nodetuple = []
			for j in range( len( offsets ) ):
				nodetuple.append( valueslist[j][i+1] )
			nextnodetuple = tuple( nodetuple )
			# before adding edge, color according to local or remote origin
			if self.pktlist[i][UDP].sport == self.lport: edgecolour = 'green'
			if self.pktlist[i][UDP].sport == self.rport: edgecolour = 'blue'
			G.add_edge( thisnodetuple, nextnodetuple, label=i , color = edgecolour )
		# clean out unused states from graph
		for n in G.nodes():
			if G.neighbors(n) ==  []: G.remove_node(n)
		GA = nx.to_agraph( G )
		GA.edge_attr['penwidth'] = 3.0
		GA.layout()
		GA.write( filename )
		if display:
			Popen( ['xdot', filename ] )
		return

class Samples(object):
	def __init__( self, convo , maxlen = 8 , bucketsize = 1):
		'''
		Samples object represents the set of payloads extracted from the conversation.
		The bulk of the analysis will be performed here using the methods exposed.

		Args:
		* convo is a conversation object
		* maxlen is the maximum number of bytes to include.
		  NOTE: all samples in the conversation should have at least this length.
		* bucketsize is the number of bytes to consider each bucket as
		
		TODO: For now, bucket size and length are number of bytes. It should be number of bits
		'''
		self.payloads = [ c[Raw].load for c in convo.pktlist ]
		self.bytelists = []
		self.bucketsize = bucketsize
		self.maxlen = maxlen
		for j in xrange( maxlen/bucketsize ):
			vlist = []
  			for i in xrange( len( self.payloads ) ):
				vlist.append( self.payloads[i][bucketsize*j:bucketsize*(j+1)] )
			self.bytelists.append( vlist )
		return
	def _mord( self, bytestr ):
		'''multibyte version of ord.'''
		return int( bytestr.encode('hex'), 16 )
	
	def sizes( self ):
		'''
		Returns a numpy array containing the length of each request.
		'''
		plens = np.array( [ len( c ) for c in self.payloads ] )
		return plens
	
	def sizeMin( self ):
		'''
		Returns the minimum length (in bytes) of the set of samples.
		'''
		return self.sizes().min()
	
	def sizeMax( self ):
		'''
		Returns the maximum length (in bytes) of the set of samples.
		'''
		return self.sizes().max()
	
	def valueList( self, offset = 'all' ):
		'''
		Returns a list of all values for each payload in the conversation by default.
		If an integer is supplied it becomes a bucket-wise offset and a list showing the
		value for that bucket is produced.
		'''
		if offset == 'all':
			return self.bytelists
		if type(offset) == type([]):
			return { o: self.bytelists[o] for o in offset }
		if type(offset) == type(1):
			return self.bytelists[ offset ] 
	
	def valueSet( self, offset = 'all' ):
		'''
		As with valueList, except returns a set which eliminates duplicates and does not preserve order.
		'''
		if offset == 'all':
			return [ set(b) for b in self.bytelists ]
		if type(offset) == type([]):
			return { o: set( self.bytelists[ o ] ) for o in offset }
		if type(offset) == type(1):
			return set( self.bytelists[ offset ] )
	
	def valueCount( self, offset = 'all' ):
		'''
		As with valueList, except returns the size of each payloa
		TODO: I think this is broken for dicts ..
		'''
		if offset == 'all':
			return [ len(s) for s in [ set(b) for b in self.bytelists ] ]
		if type(offset) == type([]):
			return { o: len(s) for s in [ set(self.bytelists[o]) for o in offset ] }
		if type(offset) == type(1):
			return len( set( self.bytelists[offset] ) )
	
	def valueMax( self, offset = 'all' ):
		'''
		As with valueList, except returns the maximum value in the indicated bucket.
		'''
		if offset == 'all':
			return [ np.array( [ self._mord(c) for c in b ] ).max() for b in self.bytelists ]
		if type(offset) == type([]):
			return { o: np.array( [ self._mord(c) for c in self.bytelists[o] ] ).max() for o in offset }
		if type(offset) == type(1):
			return	np.array( [ self._mord(c) for c in self.bytelists[offset] ] ).max()
	
	def testNonZero( self, offset = 'all' ):
		'''
		Tests a condition against each packet at the specified offset. Default is across all offsets in the sample.
		A list of offsets or single offset can be supplied, returning a dict of lists or list respecively.
		returns True of all values in the bucket were zero, false otherwise.
		'''
		if offset == 'all':
			return [ np.array( [ self._mord(c) for c in b ] ).all() for b in self.bytelists ]
		if type(offset) == type([]):
			return { o: np.array( [ self._mord(c) for c in self.bytelists[o] ] ).all() for o in offset }
		if type(offset) == type(1):
			return	np.array( [ self._mord(c) for c in self.bytelists[offset] ] ).all()
	
	def testBelow( self, value, offset = 'all' ):
		'''
		As with testAllZero, except returns True for all values in the bucket area below the given value (hex or int)
		'''
		if offset == 'all':
			return [ np.all( np.array( [ self._mord(c) for c in b ] ) < value ) for b in self.bytelists ] # return isbelow
		if type(offset) == type([]):
			return { o: np.all( np.array( [ self._mord(c) for c in self.bytelists[o] ] ) ) for o in offset }
		if type(offset) == type(1):
			return	np.array( [ self._mord(c) for c in self.bytelists[offset] ] < value )

	def testLinearity( self, offset = 'all' ):
		'''
		As with testAllZero, except returns the r-value for a linearity test.
		'''
		timeaxis = range( len( self.bytelists[0] ) )
		if offset == 'all':
			return [ ss.linregress( [ self._mord(x) for x in b ],  timeaxis )[2] for b in self.bytelists ]
		if type(offset) == type([]):
			return { o: ss.linregress( [ self._mord(x) for x in self.bytelists[o] ], timeaxis )[2] for o in offset }
		if type(offset) == type(1):
			return ss.linregress( [ self._mord(x) for x in self.bytelists[offset] ], timeaxis )[2] 
	
	def testEntropy( self, offset = 'all' ):
		'''
		As with testAllZero, except returns the shannon entryopy of values across all packets for the given offset
		TODO: this give erroneous results.
		'''
		if offset == 'all':
			return [ ss.entropy( [ self._mord(x) for x in b ] ) for b in self.bytelists ]
		if type(offset) == type([]):
			return { o: ss.entropy( [ self._mord(x) for x in self.bytelists[o] ] ) for o in offset }
		if type(offset) == type(1):
			return ss.entropy( [ self._mord(x) for x in self.bytelists[offset] ] )

	def testNormal( self, offset = 'all'):
		'''
		As with testAllZero, except returns the p-value for the normal distribution null hypothesis.
		'''
		if offset == 'all':
			return [ ss.normaltest( [ self._mord(c) for c in b] )[1] for b in self.bytelists ]
		if type(offset) == type([]):
			return { o: ss.normaltest( [ self._mord(c) for c in self.bytelists[o] ] )[1] for o in offset }
		if type(offset) == type(1):
			return ss.normaltest( [ self._mord(c) for c in self.bytelists[ offset ] ] )[1]
	
	def testChi2( self, offset = 'all' ):
		'''
		As with testAllZero, except returns the result of a chi-squared test (TODO: detail of its default behavior)
		'''
		if offset == 'all':
			return [ ss.chisquare( [ self._mord(c) for c in  b ] )[1] for b in self.bytelists ]
		if type(offset) == type([]):
			return { o: ss.chisquare( [ self._mord(c) for c in self.bytelists[o] ] )[1] for o in offset }
		if type(offset) == type(1):
			return ss.chisquare( [ self._mord(c) for c in self.bytelists[ offset ] ] )[1]
	
	def valuePlot( self, offsets = 'all' ):
		'''
		Plot the numerical value of each bucket in a timeline, each will have different colors. TODO: add key
		'''
		if offsets == 'all':
			offsets = range( len( self.bytelists ) )
		if type(offsets) == type(1):
			offsets = [ offsets ]
		if type(offsets) == type([]):
			for o in offsets:
				pl.plot( self.asDec(o), 'o' )
			pl.show()
		return
	
	def asDec( self, offset = 'all'):
		'''
		Returns each of the values as a decimal number. Offsets can be specified as for testX and valueX methods.
		'''
		if offset == 'all':
			return [ [ self._mord(c) for c in b ] for b in self.bytelists ]
		if type(offset) == type([]):
			return { o: [ self._mord(c) for c in self.bytelists[o] ] for o in offset }
		if type(offset) == type(1):
			return [ self._mord(c) for c in self.bytelists[offset] ]
	
	def asDecSet( self, offset = 'all'):
		'''
		Returns the set of values across the samples for the given offsets as decimal numbers.
		'''
		if offset == 'all':
			return [ set( [ self._mord(c) for c in b ] ) for b in self.bytelists ] 
		if type(offset) == type([]):
			return { o: set( [ self._mord(c) for c in self.bytelists[o] ] ) for o in offset }
		if type(offset) == type(1):
			return set( [ self._mord(c) for c in self.bytelists[offset] ] )
	
	def asHex( self, offset = 'all'):
		'''
		As with asDec, except returns ascii hex values.
		'''
		if offset == 'all':
			return [ [ c.encode('hex') for c in b ] for b in self.bytelists ]
		if type(offset) == type([]):
			return { o: [ [ c.encode('hex') for c in self.bytelists[o] ] for o in offset ] }
		if type(offset) == type(1):
			return [ c.encode('hex') for c in self.bytelists[offset] ]
	
	def asHexSet( self, offset = 'all'):
		'''
		As with asDecSet, except returns ascii hex values.
		'''
		if offset == 'all':
			return [ set( [ c.encode('hex') for c in b ] ) for b in self.bytelists ] 
		if type(offset) == type([]):
			return { o: set( [ c.encode('hex') for c in self.bytelists[o] ] ) for o in offset }
		if type(offset) == type(1):
			return set( [ c.encode('hex') for c in self.bytelists[offset] ] )
	
