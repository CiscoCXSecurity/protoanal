# This will throw up a couple of graphs which are pretty to look at.
# I recommend you try typing these commands into ipython.
# You will need to change values if trying protocols other thant PCoIP.
# help( pa.Conversation ) is your friend!

import protoanal as pa

c = pa.Conversation( 'test.pcap' , 50002 )

c.subrange(20).sizeHistogram()
c.subrange(20).sizes()

cs = c.subrange(20).sizeIs(52)

s = pa.Samples( cs, 16, 2 )

print s.asHexSet([0,2,4])

print s.valuePlot([0,3])

cs.statePlot( 2, [0,3] )
