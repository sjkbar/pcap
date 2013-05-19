package org.araqne.pcap.smb.ntresp;

import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.structure.FileNotifyInformation;

public class NtTransactNotifyChangeResponse implements TransData{
	FileNotifyInformation []fileNotifyInformation;

	public FileNotifyInformation[] getFileNotifyInformation() {
		return fileNotifyInformation;
	}

	public void setFileNotifyInformation(
			FileNotifyInformation[] fileNotifyInformation) {
		this.fileNotifyInformation = fileNotifyInformation;
	}
	@Override
	public String toString(){
		return String.format("Second Level : Nt Transact Notify Change Response\n"+
				"FileNotifyInformation = %s\n",
				fileNotifyInformation.toString());
	}
}
