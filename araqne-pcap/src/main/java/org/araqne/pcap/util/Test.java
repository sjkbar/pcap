package org.araqne.pcap.util;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class Test {
	public static void main(String[] args) throws UnknownHostException, IOException {
		System.loadLibrary("araqne_pcap");
		System.out.println(Arping.query(InetAddress.getByName("172.20.0.11"), 1000));
	}
}
