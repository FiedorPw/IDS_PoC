from scapy.all import rdpcap
from collections import Counter
import matplotlib.pyplot as plt
import pyshark



def load_pcap(file_name):
    return rdpcap(file_name)


def analyze_traffic(packets, known_ips, request_threshold, bandwidth_threshold):
    ip_counter = Counter()
    total_bandwidth = 0
    anomalies = {"request_threshold": 0, "unknown_source": 0, "bandwidth_threshold": 0}

    for pkt in packets:
        if 'IP' in pkt:
            ip_src = pkt['IP'].src
            ip_counter[ip_src] += 1
            total_bandwidth += len(pkt)

    # Wykrywanie anomalii
    for ip, count in ip_counter.items():
        if count > request_threshold:
            anomalies["request_threshold"] += 1
            print(f"Anomalia: Nietypowy wzrost liczby żądań z {ip}")

    for ip in ip_counter:
        if ip not in known_ips:
            anomalies["unknown_source"] += 1
            print(f"Anomalia: Ruch z nieznanego źródła IP: {ip}")

    if total_bandwidth > bandwidth_threshold:
        anomalies["bandwidth_threshold"] += 1
        print("Anomalia: Niespodziewany wzorzec przepustowości.\n")

    return anomalies


# ______________________________________________________________________________________

packet_array = []


def import_pcap(filename):
    capture = pyshark.FileCapture(filename)

    for packet in capture:
        packet_array.append(packet)


def detectNetworkScanning(packet_array):
    arpCount = 0
    arp_scan_detected = 0
    amount_arp_scan_detected = 0
    last_host = packet_array[0]

    for i in range(0, len(packet_array)):

        if packet_array[i].highest_layer == 'ARP':
            # senderIP = packet.
            arpCount += 1
            # print(f"ciąg arpów {arpCount}")
            if arpCount > 10 and arp_scan_detected == 0:
                amount_arp_scan_detected += 1
                print(f"prawdopodobne skanowanie sieci po raz {amount_arp_scan_detected}")
                arp_scan_detected = 1
        else:

            # print("nie poznaje")
            arpCount = 0
            arp_scan_detected = 0

    print(
        f"sieć była skanowana {amount_arp_scan_detected} razy(sekwencja co najmniej 10 pakietów arp z jednego hosta)\n")
    return amount_arp_scan_detected
def detectPortScanning(packet_array):
    i = 0
    array_20packets = []
    rst_count = 0
    port_scaning_detected = 0
    detected_scans_amount = 0
    for i in range(0, len(packet_array)):

        # dodawanie do arraya który bedzie miał ,,okno" 20 pakietów z całego ruchu sieciowego na kolejce FIFO
        # i bedzie sprawdzał czy przynajmniej 8 z nich to były RST
        array_20packets.append(packet_array[i])

        if packet_array[i].highest_layer == 'TCP' and int(packet_array[i].tcp.flags_reset) == 1:
            # print("super tcp reset")
            rst_count += 1
        # usuwanie z tyłu kolejki
        if len(array_20packets) >= 21:
            if array_20packets[0].highest_layer == 'TCP' and int(array_20packets[0].tcp.flags_reset) == 1:
                # print("wykopujemy rst")
                rst_count -= 1

            array_20packets.pop(0)
        if port_scaning_detected == 1 and rst_count < 5:
            port_scaning_detected = 0

        if rst_count >= 10 and port_scaning_detected == 0:
            detected_scans_amount += 1
            port_scaning_detected = 1
            print(f"prawdopodobny skan portów poraz {detected_scans_amount}")
    print(detected_scans_amount,
          f"porty hosta były skanowane {detected_scans_amount} razy (ponad 50% ostatnich pakietów ma flagę RST)")
    return detected_scans_amount
def analyze_traffic_with_scanning(anomalies):
    anomalies.update({"Network_scans": detectNetworkScanning(packet_array), "Port_Scans": detectPortScanning(packet_array)})
    return anomalies

def plot_anomalies(anomalies):
    labels, values = zip(*anomalies.items())
    plt.bar(labels, values)
    plt.xticks(fontsize=8)  # Adjust font size as needed
    plt.tight_layout()
    plt.xlabel('Rodzaj Anomalii')
    plt.ylabel('Liczba Wystąpień')
    plt.title('Wykres Wystąpień Anomalii w Ruchu Sieciowym')
    plt.show()


# Parametry
file_name = 'czescAtaku.pcapng'  # Zastąp nazwą swojego pliku PCAP
known_ips = ['192.168.0.1', '69.173.144.139']  # Zdefiniuj znane adresy IP
request_threshold = 100  # Próg dla liczby żądań
bandwidth_threshold = 10000  # Próg dla przepustowości (w bajtach)

# Wczytywanie i analiza danych z pliku PCAP
packets = load_pcap(file_name)
import_pcap(file_name)
print(len(packet_array))
anomalies = analyze_traffic(packets, known_ips, request_threshold, bandwidth_threshold)

detectNetworkScanning(packet_array)
detectPortScanning(packet_array)
anomalies_and_scanning = analyze_traffic_with_scanning(anomalies)

# Wizualizacja anomalii
plot_anomalies(anomalies_and_scanning)
