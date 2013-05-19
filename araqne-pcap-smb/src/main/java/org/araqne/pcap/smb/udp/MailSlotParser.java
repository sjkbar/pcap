package org.araqne.pcap.smb.udp;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class MailSlotParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer, Buffer parameterBuffer,
			Buffer DataBuffer){
		TransData data = new MailSlot();
		((MailSlot)data).setMailslotCode(ByteOrderConverter.swap(setupBuffer.getShort()));
		((MailSlot)data).setPriority(ByteOrderConverter.swap(setupBuffer.getShort()));
		((MailSlot)data).setCls(ByteOrderConverter.swap(setupBuffer.getShort()));
		return data;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer, Buffer parameterBuffer,
			Buffer DataBuffer, SmbSession session) {
		return null;
	}

	@Override
	public String toString() {
		return "MailSlotParser [toString()=" + super.toString() + "]";
	}


}
