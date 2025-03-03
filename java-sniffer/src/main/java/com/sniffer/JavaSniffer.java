package com.sniffer;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import java.util.List;

public class JavaSniffer {
    public static void main(String[] args) {
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            if (interfaces == null || interfaces.isEmpty()) {
                System.out.println("No network interfaces found.");
                return;
            }

            PcapNetworkInterface networkInterface = interfaces.get(0);
            System.out.println("Using interface: " + networkInterface.getName());

            PcapHandle handle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

            System.out.println("Listening for packets...");
            handle.loop(10, (Packet packet) -> System.out.println("Captured packet: " + packet));

            handle.close();
        } catch (PcapNativeException | NotOpenException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}
