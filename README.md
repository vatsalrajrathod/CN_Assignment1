
# Assignment Results

This repository contains solutions to the assignment, which involve analyzing network traffic using various tools like **tcpreplay**, **Wireshark**, and Python libraries. Please follow the instructions below to reproduce the results that have been submitted.

## Prerequisites

Before you begin, ensure you have the following tools installed on your system:

- **tcpreplay**: To replay network traffic from a `.pcap` file.
- **Wireshark**: To analyze network traffic.
- **matplotlib**: Python library for plotting graphs.
- **Python 3.8.10**: Make sure Python 3.8.10 is installed on your system.
- **scapy**: Python library for network packet manipulation.
- **pyshark**: Python library to analyze pcap files.

You can install the required dependencies using the following commands:

```
# Install tcpreplay
sudo apt-get install tcpreplay

# Install Wireshark
sudo apt-get install wireshark

# Install Python 3.8.10 (if not already installed)
sudo apt install python3.8

# Install required Python libraries
pip install matplotlib scapy pyshark
```

## Clone the Repository

Start by cloning the repository:

```
git clone https://github.com/your-username/your-repository.git
cd your-repository
```

## Task Instructions

### Q1: Network Traffic Replay and Histogram

1. **Open two terminals** in parallel.

2. In the first terminal, run the following command to execute the Python script `Q1.py`:

    ```
    sudo tcpdump -i enp0s3 -w captured.output
    ```

3. In the second terminal, replay the `.pcap` file using **tcpreplay**:

    ```
    sudo tcpreplay -i enp0s3 -t 10000 2.pcap
    ```

    > **Note**: Replace `enp0s3` with the appropriate network interface on your system. You can find the interface name using the `ifconfig` or `ip a` command.

4. Run the Q1.py and the results will be saved in a text file. You can open the text file to inspect the output.

5. **Plotting the Histogram**: To plot the histogram of the packet sizes, use the data from the result text file. Here is an example Python code to plot the histogram:

    ```
    import matplotlib.pyplot as plt
    import numpy as np

    # Replace with your actual data from the result file
    counts = np.array([306, 8, 3, 11, 1, 2, 2, 5, 0, 2, 50, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    bin_edges = np.array([42., 184.46, 326.92, 469.38, 611.84, 754.3, 896.76,
                          1039.22, 1181.68, 1324.14, 1466.6, 1609.06, 1751.52, 1893.98,
                          2036.44, 2178.9, 2321.36, 2463.82, 2606.28, 2748.74, 2891.2,
                          3033.66, 3176.12, 3318.58, 3461.04, 3603.5, 3745.96, 3888.42,
                          4030.88, 4173.34, 4315.8, 4458.26, 4600.72, 4743.18, 4885.64,
                          5028.1, 5170.56, 5313.02, 5455.48, 5597.94, 5740.4, 5882.86,
                          6025.32, 6167.78, 6310.24, 6452.7, 6595.16, 6737.62, 6880.08,
                          7022.54, 7165.])

    # Plot the histogram
    plt.hist(bin_edges[:-1], bins=bin_edges, weights=counts, edgecolor='black')
    plt.xlabel('Packet Size')
    plt.ylabel('Frequency')
    plt.title('Histogram of Packet Sizes')
    plt.grid(True)
    plt.show()
    ```

6. **Result**: The histogram of packet sizes will be displayed.

---

### Q2: Running the Q2.py Script

To run the script for Q2:

```
sudo python3 Q2.py
```

This will execute the task and generate the necessary output. Make sure you have the required permissions to execute the script.

---

### Q3: Inspecting Websites

For Q3, the results can be obtained by inspecting the websites directly. You can refer to the provided PDF file for the final output and findings.

---

## Conclusion

After following the instructions above, you should be able to reproduce the results that were submitted. If you face any issues or need further clarification, feel free to open an issue in this repository.

---
