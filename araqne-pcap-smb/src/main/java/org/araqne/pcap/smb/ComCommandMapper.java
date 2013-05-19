package org.araqne.pcap.smb;

import java.util.HashMap;
import java.util.Map;

import org.araqne.pcap.smb.comparser.CheckDirectoryParser;
import org.araqne.pcap.smb.comparser.CloseAndTreeDiscParser;
import org.araqne.pcap.smb.comparser.CloseParser;
import org.araqne.pcap.smb.comparser.ClosePrintFileParser;
import org.araqne.pcap.smb.comparser.CopyParser;
import org.araqne.pcap.smb.comparser.CreateDirectoryParser;
import org.araqne.pcap.smb.comparser.CreateNewParser;
import org.araqne.pcap.smb.comparser.CreateParser;
import org.araqne.pcap.smb.comparser.CreateTemporaryParser;
import org.araqne.pcap.smb.comparser.DeleteDirectoryParser;
import org.araqne.pcap.smb.comparser.DeleteParser;
import org.araqne.pcap.smb.comparser.EchoParser;
import org.araqne.pcap.smb.comparser.FindClose2Parser;
import org.araqne.pcap.smb.comparser.FindCloseParser;
import org.araqne.pcap.smb.comparser.FindNotifyCloseParser;
import org.araqne.pcap.smb.comparser.FindParser;
import org.araqne.pcap.smb.comparser.FindUniqueParser;
import org.araqne.pcap.smb.comparser.FlushParser;
import org.araqne.pcap.smb.comparser.GetPrintQueueParser;
import org.araqne.pcap.smb.comparser.IOCTLParser;
import org.araqne.pcap.smb.comparser.IOCTLSecondaryParser;
import org.araqne.pcap.smb.comparser.InvalidParser;
import org.araqne.pcap.smb.comparser.LockAndReadParser;
import org.araqne.pcap.smb.comparser.LockByteRangeParser;
import org.araqne.pcap.smb.comparser.LockingANDXParser;
import org.araqne.pcap.smb.comparser.LogoffANDXParser;
import org.araqne.pcap.smb.comparser.MoveParser;
import org.araqne.pcap.smb.comparser.NegotiateParser;
import org.araqne.pcap.smb.comparser.NewFileSizeParser;
import org.araqne.pcap.smb.comparser.NoANDXCommandParser;
import org.araqne.pcap.smb.comparser.NtCancelParser;
import org.araqne.pcap.smb.comparser.NtCreateANDXParser;
import org.araqne.pcap.smb.comparser.NtTransactParser;
import org.araqne.pcap.smb.comparser.NtTransactSecondaryParser;
import org.araqne.pcap.smb.comparser.OpenANDXParser;
import org.araqne.pcap.smb.comparser.OpenParser;
import org.araqne.pcap.smb.comparser.OpenPrintFileParser;
import org.araqne.pcap.smb.comparser.ProcessExitParser;
import org.araqne.pcap.smb.comparser.QueryInfo2Parser;
import org.araqne.pcap.smb.comparser.QueryInfoDiskParser;
import org.araqne.pcap.smb.comparser.QueryInfoParser;
import org.araqne.pcap.smb.comparser.QueryServerParser;
import org.araqne.pcap.smb.comparser.ReadANDXParser;
import org.araqne.pcap.smb.comparser.ReadBulkParser;
import org.araqne.pcap.smb.comparser.ReadMPXParser;
import org.araqne.pcap.smb.comparser.ReadMPXSecondaryParser;
import org.araqne.pcap.smb.comparser.ReadParser;
import org.araqne.pcap.smb.comparser.ReadRawParser;
import org.araqne.pcap.smb.comparser.RenameParser;
import org.araqne.pcap.smb.comparser.SearchParser;
import org.araqne.pcap.smb.comparser.SecurityPackageANDXParser;
import org.araqne.pcap.smb.comparser.SeekParser;
import org.araqne.pcap.smb.comparser.SessionSetupANDXParser;
import org.araqne.pcap.smb.comparser.SetInfo2Parser;
import org.araqne.pcap.smb.comparser.SetInfoParser;
import org.araqne.pcap.smb.comparser.SmbDataParser;
import org.araqne.pcap.smb.comparser.Transaction2Parser;
import org.araqne.pcap.smb.comparser.TransactionParser;
import org.araqne.pcap.smb.comparser.TransactionSecondaryParser;
import org.araqne.pcap.smb.comparser.TreeConnectANDXParser;
import org.araqne.pcap.smb.comparser.TreeConnectParser;
import org.araqne.pcap.smb.comparser.TreeDisconnectParser;
import org.araqne.pcap.smb.comparser.UnlockByteRangeParser;
import org.araqne.pcap.smb.comparser.WriteANDXParser;
import org.araqne.pcap.smb.comparser.WriteAndCloseParser;
import org.araqne.pcap.smb.comparser.WriteAndUnlockParser;
import org.araqne.pcap.smb.comparser.WriteBulkDataParser;
import org.araqne.pcap.smb.comparser.WriteCompleteParser;
import org.araqne.pcap.smb.comparser.WriteMPXParser;
import org.araqne.pcap.smb.comparser.WriteMPXSecondaryParser;
import org.araqne.pcap.smb.comparser.WriteParser;
import org.araqne.pcap.smb.comparser.WritePrintFileParser;
import org.araqne.pcap.smb.comparser.WriteRawParser;
import org.araqne.pcap.smb.rr.SmbCommand;

public class ComCommandMapper {

	private Map<SmbCommand , SmbDataParser> parsers;
	ComCommandMapper()
	{
		parsers = new HashMap<SmbCommand, SmbDataParser>();
		map(SmbCommand.SMB_COM_DELETE_DIRECTORY, new DeleteDirectoryParser());
		map(SmbCommand.SMB_COM_OPEN, new OpenParser());
		map(SmbCommand.SMB_COM_CREATE, new CreateParser());
		map(SmbCommand.SMB_COM_CLOSE, new CloseParser());
		map(SmbCommand.SMB_COM_FLUSH, new FlushParser());
		map(SmbCommand.SMB_COM_DELETE, new DeleteParser());
		map(SmbCommand.SMB_COM_RENAME, new RenameParser());
		map(SmbCommand.SMB_COM_QUERY_INFORMATION, new QueryInfoParser());
		map(SmbCommand.SMB_COM_READ, new ReadParser());
		map(SmbCommand.SMB_COM_WRITE, new WriteParser());
		map(SmbCommand.SMB_COM_LOCK_BYTE_RANGE, new LockByteRangeParser());
		map(SmbCommand.SMB_COM_CREATE_TEMPORARY, new CreateTemporaryParser());
		map(SmbCommand.SMB_COM_CREATE_NEW, new CreateNewParser());
		map(SmbCommand.SMB_COM_CREATE_DIRECTORY, new CreateDirectoryParser());
		map(SmbCommand.SMB_COM_PROCESS_EXIT, new ProcessExitParser());
		map(SmbCommand.SMB_COM_SEEK, new SeekParser());
		map(SmbCommand.SMB_COM_LOCK_AND_READ, new LockAndReadParser());
		map(SmbCommand.SMB_COM_WRITE_AND_UNLOCK, new WriteAndUnlockParser());
		map(SmbCommand.SMB_COM_READ_RAW, new ReadRawParser());
		map(SmbCommand.SMB_COM_READ_MPX, new ReadMPXParser());
		map(SmbCommand.SMB_COM_READ_MPX_SECONDARY, new ReadMPXSecondaryParser());
		map(SmbCommand.SMB_COM_WRITE_RAW, new WriteRawParser());
		map(SmbCommand.SMB_COM_WRITE_MPX, new WriteMPXParser());
		map(SmbCommand.SMB_COM_WRITE_MPX_SECONDARY,
				new WriteMPXSecondaryParser());
		map(SmbCommand.SMB_COM_UNLOCK_BYTE_RANGE , new UnlockByteRangeParser());
		map(SmbCommand.SMB_COM_WRITE_COMPLETE, new WriteCompleteParser());
		map(SmbCommand.SMB_COM_QUERY_SERVER, new QueryServerParser());
		map(SmbCommand.SMB_COM_SET_INFORMATION2, new SetInfo2Parser());
		map(SmbCommand.SMB_COM_QUERY_INFORMATION2, new QueryInfo2Parser());
		map(SmbCommand.SMB_COM_LOCKING_ANDX, new LockingANDXParser());
		map(SmbCommand.SMB_COM_TRANSACTION, new TransactionParser());
		map(SmbCommand.SMB_COM_TRANSACTION_SECONDARY,
				new TransactionSecondaryParser());
		map(SmbCommand.SMB_COM_IOCTL, new IOCTLParser());
		map(SmbCommand.SMB_COM_IOCTL_SECONDARY, new IOCTLSecondaryParser());
		map(SmbCommand.SMB_COM_COPY, new CopyParser());
		map(SmbCommand.SMB_COM_MOVE, new MoveParser());
		map(SmbCommand.SMB_COM_ECHO, new EchoParser());
		map(SmbCommand.SMB_COM_WRITE_AND_CLOSE, new WriteAndCloseParser());
		map(SmbCommand.SMB_COM_OPEN_ANDX, new OpenANDXParser());
		map(SmbCommand.SMB_COM_READ_ANDX, new ReadANDXParser());
		map(SmbCommand.SMB_COM_WRITE_ANDX, new WriteANDXParser());
		map(SmbCommand.SMB_COM_NEW_FILE_SIZE, new NewFileSizeParser());
		map(SmbCommand.SMB_COM_CLOSE_AND_TREE_DISC,
				new CloseAndTreeDiscParser());
		map(SmbCommand.SMB_COM_TRANSACTION2, new Transaction2Parser());
		map(SmbCommand.SMB_COM_TRANSACTION2_SECONDARY, new Transaction2Parser());
	//	map(SmbCommand.SMB_COM_TRANSACTION2_SECONDARY,
	//			new Transaction2SecondaryParser());
		map(SmbCommand.SMB_COM_FIND_CLOSE2, new FindClose2Parser());
		map(SmbCommand.SMB_COM_FIND_NOTIFY_CLOSE, new FindNotifyCloseParser());
		map(SmbCommand.SMB_COM_TREE_CONNECT, new TreeConnectParser());
		map(SmbCommand.SMB_COM_TREE_DISCONNECT, new TreeDisconnectParser());
		map(SmbCommand.SMB_COM_NEGOTIATE, new NegotiateParser());
		map(SmbCommand.SMB_COM_SESSION_SETUP_ANDX, new SessionSetupANDXParser());
		map(SmbCommand.SMB_COM_LOGOFF_ANDX, new LogoffANDXParser());
		map(SmbCommand.SMB_COM_TREE_CONNECT_ANDX, new TreeConnectANDXParser());
		map(SmbCommand.SMB_COM_SECURITY_PACKAGE_ANDX,
				new SecurityPackageANDXParser());
		map(SmbCommand.SMB_COM_QUERY_INFORMATION_DISK,
				new QueryInfoDiskParser());
		map(SmbCommand.SMB_COM_SEARCH, new SearchParser());
		map(SmbCommand.SMB_COM_FIND, new FindParser());
		map(SmbCommand.SMB_COM_FIND_UNIQUE, new FindUniqueParser());
		map(SmbCommand.SMB_COM_FIND_CLOSE, new FindCloseParser());
		map(SmbCommand.SMB_COM_NT_TRANSACT_SECONDARY,
				new NtTransactSecondaryParser());
		map(SmbCommand.SMB_COM_NT_TRANSACT,	new NtTransactParser());
		map(SmbCommand.SMB_COM_NT_CREATE_ANDX, new NtCreateANDXParser());
		map(SmbCommand.SMB_COM_NT_CANCEL, new NtCancelParser());
		map(SmbCommand.SMB_COM_NT_RENAME, new RenameParser());
		map(SmbCommand.SMB_COM_OPEN_PRINT_FILE, new OpenPrintFileParser());
		map(SmbCommand.SMB_COM_WRITE_PRINT_FILE, new WritePrintFileParser());
		map(SmbCommand.SMB_COM_CLOSE_PRINT_FILE, new ClosePrintFileParser());
		map(SmbCommand.SMB_COM_GET_PRINT_QUEUE, new GetPrintQueueParser());
		map(SmbCommand.SMB_COM_READ_BULK, new ReadBulkParser());
		// map(SmbCommand.SMB_COM_WRITE_BULK, new WriteBulkParser());
		map(SmbCommand.SMB_COM_WIRTE_BULK_DATA, new WriteBulkDataParser());
		map(SmbCommand.SMB_COM_INVALID, new InvalidParser());
		map(SmbCommand.SMB_COM_NO_ANDX_COMMAND, new NoANDXCommandParser());
		map(SmbCommand.SMB_COM_SET_INFORMATION , new SetInfoParser());
		map(SmbCommand.SMB_COM_CHECK_DIRECTORY , new CheckDirectoryParser());
	}

	private void map(SmbCommand command, SmbDataParser parser) {
		parsers.put(command, parser);
	}
	public SmbDataParser getComParser(SmbCommand command)
	{
		return parsers.get(command);
	}
}
