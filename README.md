# AutomaticProtocolAnalysis
Python3 scripts that analyze protocols in the recorded PCAP(s) to a CSV file.

# Requirements
Python 3.6 or newer
`pip3 install pyshark`

# Usage
Put the recorded pcap(s) in the `pcaps` directory and run `python3 analyzepcaps.py`. A CSV file will be generated in the `stats` directory.

The `analyzeprotocolspergame.py` script could further analyze the CSV files to make a summary of the count of protocols used in total by the pcaps in question.
