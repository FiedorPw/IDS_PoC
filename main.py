import pyshark

def import_pcap(filename):
    capture = pyshark.FileCapture(filename)
    return capture

def checkSenderIp(packet):
    if 'IP' in packet:
        sender_ip = packet['IP'].src

    elif 'ARP' in packet:
        sender_ip = packet['ARP'].psrc
        print(f"Sender IP (from ARP): {sender_ip}")
    else:
        print("Packet does not contain an IP or ARP layer.")
    return sender_ip

#importujemy pakiety i tworzymy z nich liste
capture = import_pcap('czescAtaku.pcapng')
packet_array = []
for packet in capture:
    packet_array.append(packet)

    # print(packet.highest_layer)


# first_packet = capture[0]
# first_packet_ip = capture[0].ip
# arp_packet = packet_array[187]
# arp_packet = capture[300]


# arp_packet_ip = capture[187]

# print("\n____________________________\n", first_packet)
# print("\n____________________________\n", first_packet_ip)
#
# # wykrywanie ip które zapodaje sporo SYN
# for packet in capture:
#     if 'TCP' in packet and packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
#         print(f"Possible SYN Flood attack packet: {packet.ip.src} -> {packet.ip.dst}")
#
print("ilość pobranych pakietów do analizy: ",len(packet_array),"\n")

def detectNetworkScanning(packet_array):
    arpCount = 0
    arp_scan_detected = 0
    amount_arp_scan_detected = 0
    last_host = packet_array[0]

    for i in range(0,len(packet_array)):


        if  packet_array[i].highest_layer=='ARP':
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

    print(f"sieć była skanowana {amount_arp_scan_detected} razy(sekwencja co najmniej 10 pakietów arp z jednego hosta)\n")

def detectPortScanning(packet_array):
    i = 0
    array_20packets = []
    rst_count = 0
    port_scaning_detected = 0
    detected_scans_amount = 0
    for i in range(0, len(packet_array)):

        #dodawanie do arraya który bedzie miał ,,okno" 20 pakietów z całego ruchu sieciowego na kolejce FIFO
        # i bedzie sprawdzał czy przynajmniej 8 z nich to były RST
        array_20packets.append(packet_array[i])

        if packet_array[i].highest_layer == 'TCP' and int(packet_array[i].tcp.flags_reset) == 1:
            # print("super tcp reset")
            rst_count += 1
        # usuwanie z tyłu kolejki
        if len(array_20packets) >= 21:
            if  array_20packets[0].highest_layer == 'TCP' and int(array_20packets[0].tcp.flags_reset) == 1:
                # print("wykopujemy rst")
                rst_count -= 1

            array_20packets.pop(0)
        if port_scaning_detected == 1 and rst_count < 5:
            port_scaning_detected = 0

        if rst_count >= 10 and port_scaning_detected == 0:
            detected_scans_amount += 1
            port_scaning_detected = 1
            print(f"prawdopodobny skan portów poraz {detected_scans_amount}")
    print(detected_scans_amount, f"porty hosta były skanowane {detected_scans_amount} razy (ponad 50% ostatnich pakietów ma flagę RST)")

detectNetworkScanning(packet_array)

detectPortScanning(packet_array)


