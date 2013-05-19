package org.araqne.pcap.tftp;

import java.io.InputStream;

public interface TftpProcessor {
	void onCommand(String command);

	void onExtractFile(InputStream is, String fileName);
}
