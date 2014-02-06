package org.araqne.pcap.http;

import java.io.File;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

import org.araqne.pcap.Protocol;
import org.araqne.pcap.decoder.ethernet.MacAddress;
import org.araqne.pcap.decoder.udp.UdpPacket;
import org.araqne.pcap.decoder.udp.UdpProcessor;
import org.araqne.pcap.live.PcapDevice;
import org.araqne.pcap.live.PcapDeviceManager;
import org.araqne.pcap.util.Arping;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.Checksum;
import org.araqne.pcap.util.IpConverter;
import org.araqne.pcap.util.PcapFileRunner;
import org.araqne.pcap.util.PcapLiveRunner;

public class DumpRunner {
	PcapDevice device;
	
	private static short calcUdpChecksum(short[] iph, short[] udph, ByteBuffer data) {
		int length = 20;
		int headerWordCount = 10;
		int dataLength = data.remaining();
 
		// calculate total length and allocate buffer
		length += dataLength;
		boolean padding = dataLength % 2 == 1;
		if (padding)
			length++; // padding
 
		short[] words = new short[length / 2];
 
		// pseudo header
		ByteBuffer header = ByteBuffer.allocate(20);
		header.putShort(iph[6]);
		header.putShort(iph[7]);
		header.putShort(iph[8]);
		header.putShort(iph[9]);
		header.putShort((short) 0x11);
		header.putShort((short) (8 + dataLength));
 
		// udp header
		header.putShort(udph[0]);
		header.putShort(udph[1]);
		header.putShort((short) (8 + dataLength));
		header.putShort((short) 0);
		header.flip();
 
		for (int i = 0; i < headerWordCount; i++)
			words[i] = header.getShort();
 
		int limit = words.length - headerWordCount;
		if (padding)
			limit--;
 
		for (int i = 0; i < limit; i++)
			words[headerWordCount + i] = data.getShort();
 
		if (padding)
			words[words.length - 1] = (short) (data.get() << 8);
 
		return (short) Checksum.sum(words);
	}

	private String srcIp;
	private String dstIp;
	private int dstPort;
	private MacAddress srcMac;
	private MacAddress dstMac;
	private int srcIpNum;
	private int dstIpNum;
	private static final int ARP_TIMEOUT = 3000;
	
	private MacAddress getDstMac(String dstIp) throws IOException, UnknownHostException {
		return Arping.query(InetAddress.getByName(dstIp), ARP_TIMEOUT);
	}

	public void SendSyslog(String format, String pri, String srcIp, String dstIp, int dstPort) throws IOException {
//		this.device = PcapDeviceManager.openFor(dstIp, 1000);
//		this.format = format;
//		this.header = "<" + pri + ">";
		this.srcIp = srcIp;
		this.dstIp = dstIp;
		this.dstPort = dstPort;
		//this.srcMac = getDstMac(srcIp);//device.getMetadata().getMacAddress();
		//this.dstMac = getDstMac(dstIp);
		this.srcIpNum = IpConverter.toInt((Inet4Address) InetAddress.getByName(srcIp));
		this.dstIpNum = IpConverter.toInt((Inet4Address) InetAddress.getByName(dstIp));
 
//		this.formatter = new JsonFormatter();
//		if (slog.isDebugEnabled())
//			slog.debug("logpresso pcap: open pcap device [{}] to send syslog", device);
	}

	private void sendSyslog(String s) throws IOException {
		if (s == null)
			return;
 
		byte[] b = s.getBytes();
 
		int totalLen = 42 + b.length;
		ByteBuffer bb = ByteBuffer.allocate(totalLen);

		byte mac[] = new byte[6];
		mac[0] = (byte)0x00;
		mac[1] = (byte)0x1d;
		mac[2] = (byte)0xb5;
		mac[3] = (byte)0x8c;
		mac[4] = (byte)0x06;
		mac[5] = (byte)0x80;
	
		// eth (14b)
//		bb.put(dstMac.getBytes());
//		bb.put(srcMac.getBytes());
		bb.put(mac);
		mac[0] = (byte)0xa8;
		mac[1] = (byte)0x20;
		mac[2] = (byte)0x66;
		mac[3] = (byte)0x1b;
		mac[4] = (byte)0x76;
		mac[5] = (byte)0x58;//9

		bb.put(mac);
		bb.putShort((short) 0x0800);
 
		// ip (20b)
		short[] iph = new short[10];
		iph[0] = (short) 0x4500; // ver + tos
		iph[1] = (short) (totalLen - 14); // length
		iph[2] = (short) 0; // id
		iph[3] = (short) 0x4000; // don't fragment
		iph[4] = (short) 0x4011; // ttl + proto
		iph[5] = 0;
		iph[6] = (short) (srcIpNum >> 16);
		iph[7] = (short) (srcIpNum);
		iph[8] = (short) (dstIpNum >> 16);
		iph[9] = (short) dstIpNum;
 
		for (int i = 0; i < 5; i++)
			bb.putShort(iph[i]);
 
		bb.putShort((short) Checksum.sum(iph));
 
		for (int i = 6; i < 10; i++)
			bb.putShort(iph[i]);
 
		// udp (8b)
		short[] udph = new short[4];
		udph[1] = (short) dstPort;
		udph[2] = (short) (b.length + 8);
		udph[3] = calcUdpChecksum(iph, udph, ByteBuffer.wrap(b));
 
		for (short h : udph)
			bb.putShort(h);
 
		bb.put(b);
 
		// payload
		//for(;;)
		device.write(bb.array());
	}
	
	public void run() throws IOException
	{
	for(;;)
	{
		device = PcapDeviceManager.openFor("172.20.0.118", 100);
		PcapLiveRunner r = new PcapLiveRunner(device);
		r.getUdpDecoder().registerUdpProcessor(new UdpProcessor() {

			public long size = 0, last = 0;
			
			@Override
			public void process(UdpPacket pkt) {
				int len = pkt.getData().readableBytes();
				byte[] b = new byte[len];
				pkt.getData().gets(b);
				size += b.length;
				long cur = System.currentTimeMillis();
				if(cur-last > 1000)
				{
					System.out.println(""+size);
					last = cur;
					size=0;
				}
			}});
		SendSyslog("","","172.20.0.152","172.20.0.1",12345);
		for(int i=0;i<100000;i++)
		{
/*			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
			}*/
			
		sendSyslog("_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1_________1");
		}
		r = null;
		device.close();
		device = null;
		System.out.println("run!!!!");
	}
		//r.setTcpProcessor(Protocol.HTTP, http);
		//r.run();		
	}
	
	public static void main(String[] args) throws IOException {
/*		HttpDecoder http = new HttpDecoder();
		http.register(new HttpProcessor() {

			@Override
			public void onRequest(HttpRequest req) {
				System.out.println(req.getMethod() + " " + req.getURL());
			}

			@Override
			public void onResponse(HttpRequest req, HttpResponse resp) {
			}

			@Override
			public void onMultipartData(Buffer buffer) {
			}});
*/		
		//PcapFileRunner r = new PcapFileRunner(new File("dump.pcap"));
		DumpRunner dr = new DumpRunner();
		dr.run();
	}
}
