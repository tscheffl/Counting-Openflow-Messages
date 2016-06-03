# Counting OpenFlow Messages 


TCP Packets between OpenFlow Controller and Switch may contain multiple OpenFlow Messages. This makes it difficult to
produce meaningful statistics and plots in Wireshark.

This small C-program parses a pcap-file and counts all **Packet\_IN** and **Packet\_OUT** Messages happening
in Intervalls of 0.01 seconds.  
It requires a pcap-file as a command line argument.

## Installing
 
The source needs to be compiled (tested on Linux and MacOS):

`clang -o sniff sniff.c -lpcap` or  
`gcc   -o sniff sniff.c -lpcap`  
 
 
## Preparing the pcap-file

**The parsing is currently not very robust.**  
In order to work, the pcap-file must be preprocessed by Wireshark and should only contain OpenFlow Messages.  
It needs to be saved by Wireshark in the TCPDUMP format. 

The follwoing display filter can be used in Wireshark to do the necessary filtering:
`openflow_v4.type == 10 or openflow_v4.type == 13`


## Running the program
The program can be run like this:  
`./sniff test.pcap`

It prints out some information for every OF-Message it encounters on the screen
and writes message-statistics to the file`of_message_stats.csv`.
 
## Graphing the output
The program produces an output file `of_message_stats.csv`.   
**Attention: This file gets overwritten every time the program runs!**
  
It contains 3 columns of data: 

  * The first column charts the cumulative time since the arrival of the first packet.  
  * The second column counts Packet_IN events in the current interval.
  * The third column counts Packet_Out events in the current interval.

The last line is a summary of all the Packet\_IN and Packet\_OUT messages seen in the pcap-File.

### Plotting with GNUPLOT

The CSV-Data can be easily plotted with Gnuplot.   

This can even be done online at <http://gnuplot.respawned.com>.  
Paste your data from the CSV-file into the Data-Window (exclude the summary line):

```
0.000000        1       0
0.106867        13      0
0.150479        5       1
0.265125        0       7
0.303235        4       10
0.415504        0       1
0.456973        0       4
```

Paste the following code in the Plot Script-Window:

```
# Scale font and line width (dpi) by changing the size! It will always display stretched.
set terminal svg size 500,300 enhanced fname 'arial'  fsize 10 butt solid
set output 'out.svg'

# Key means label...
set key inside top right
set xlabel 'Time in Seconds'
set ylabel 'OF messages'
set title 'Openflow 1000 users 50ms delay'
set style fill solid
set boxwidth 0.005
plot  "data.txt" using 1:2 title 'Packet-in' with boxes, \
      "data.txt" using ($1+0.005):3 title 'Packet-out' with boxes
```

###Enjoy the result!

 ![](graph.png)







