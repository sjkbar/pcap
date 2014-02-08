package org.araqne.pcap;

import java.io.IOException;

import org.araqne.pcap.live.PcapDevice;
import org.araqne.pcap.live.PcapDeviceManager;
import org.araqne.pcap.util.PcapLiveRunner;

public class Test {
	public static void main(String[] args) throws IOException {
		PcapDevice device = PcapDeviceManager.openFor("8.8.8.8", 10000);
		PcapLiveRunner runner = new PcapLiveRunner(device);
		runner.run();
	}
}
