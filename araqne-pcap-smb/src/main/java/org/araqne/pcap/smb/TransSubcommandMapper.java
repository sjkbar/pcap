package org.araqne.pcap.smb;

import java.util.HashMap;
import java.util.Map;


import org.araqne.pcap.smb.rr.TransactionCommand;
import org.araqne.pcap.smb.transparser.CallNmpipeParser;
import org.araqne.pcap.smb.transparser.PeekNmpipeParser;
import org.araqne.pcap.smb.transparser.QueryNmpipeInfoParser;
import org.araqne.pcap.smb.transparser.RawReadNmpipeParser;
import org.araqne.pcap.smb.transparser.RawWriteNmpipeParser;
import org.araqne.pcap.smb.transparser.ReadNmpipeParser;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.smb.transparser.TransactNmpipeParser;
import org.araqne.pcap.smb.transparser.WaitNmpipeParser;
import org.araqne.pcap.smb.transparser.WriteNmpipeParser;
import org.araqne.pcap.smb.transparser.setNmpipeStateParser;

public class TransSubcommandMapper {
	private Map<TransactionCommand, TransParser> parsers;

	public TransSubcommandMapper() {
		parsers = new HashMap<TransactionCommand, TransParser>();
		map(TransactionCommand.TRANS_SET_NMPIPE_STATE , new setNmpipeStateParser());
		map(TransactionCommand.TRANS_CALL_NMPIPE, new CallNmpipeParser());
		//map(TransactionCommand.TRANS_MAILSLOT_WRITE, new CallNmpipeParser()); // now not use this
		//TRANS_MAILSLOT_WRITE(0x0001),
		map(TransactionCommand.TRANS_RAW_READ_NMPIPE , new RawReadNmpipeParser() );
		map(TransactionCommand.TRANS_QUERY_NMPIPE_INFO, new QueryNmpipeInfoParser());
		map(TransactionCommand.TRANS_PEEK_NMPIPE, new PeekNmpipeParser());
		map(TransactionCommand.TRANS_TRANSACT_NMPIPE , new TransactNmpipeParser());
		map(TransactionCommand.TRANS_RAW_WRITE_NMPIPE , new RawWriteNmpipeParser());
		map(TransactionCommand.TRANS_READ_NMPIPE , new ReadNmpipeParser());
		map(TransactionCommand.TRANS_WRITE_NMPIPE, new WriteNmpipeParser());
		map(TransactionCommand.TRANS_WAIT_NMPIPE , new WaitNmpipeParser() );
		map(TransactionCommand.TRANS_CALL_NMPIPE , new CallNmpipeParser());
	}
	
	private void map(TransactionCommand command, TransParser parser) {
		parsers.put(command, parser);
	}
	public TransParser getParser(TransactionCommand code){
//		System.out.println("this command = " + code);
		return parsers.get(code);
	}
}
