package org.araqne.pcap.smb.response;
import org.araqne.pcap.smb.structure.SmbData;

public class NewFileSizeResponse implements SmbData{

	boolean malformed = false;
	//// not implemented
	//  return STATUS_NOT_IMPLEMENTED
	@Override
	public boolean isMalformed() {
		// TODO Auto-generated method stub
		return malformed;
	}
	@Override
	public void setMalformed(boolean malformed) {
		this.malformed = malformed;
	}
	@Override
	public String toString(){
		return String.format("First Level : New File Size Response \n" +
				"isMalformed = %s\n",
				this.malformed);
	}
}
