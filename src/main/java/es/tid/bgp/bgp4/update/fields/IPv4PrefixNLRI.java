package es.tid.bgp.bgp4.update.fields;

import es.tid.bgp.bgp4.update.tlv.BGP4TLVFormat;
import es.tid.bgp.bgp4.update.tlv.LocalNodeDescriptorsTLV;
import es.tid.bgp.bgp4.update.tlv.RoutingUniverseIdentifierTypes;
import es.tid.bgp.bgp4.update.tlv.node_link_prefix_descriptor_subTLVs.*;

import java.util.logging.Logger;
/**
 * 
 * @author ogondio
 *
 */
public class IPv4PrefixNLRI extends LinkStateNLRI {
	
	private int protocolID;
	private long routingUniverseIdentifier;
	private LocalNodeDescriptorsTLV localNodeDescriptors;
	private OSPFRouteTypeTLV OSPFRouteType;
	private IPReachabilityInformationTLV ipReachability;
	//private IPReachabilityInfo IPReachabilityINFO;
	
	public IPv4PrefixNLRI() {
		this.setNLRIType(NLRITypes.Prefix_v4_NLRI);
		this.setRoutingUniverseIdentifier(RoutingUniverseIdentifierTypes.Level3Identifier);
	}

	

	public IPv4PrefixNLRI(byte[] bytes, int offset) {
		super(bytes, offset);
		decode();
		// TODO Auto-generated constructor stub
	}
	
@Override
	public void encode() {
	
		/*
		 *       0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+
     |  Protocol-ID  |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           Identifier                          |
     |                            (64 bits)                          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     //              Local Node Descriptors (variable)              //
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     //                Prefix Descriptors (variable)                //
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Figure 9: The IPv4/IPv6 Topology Prefix NLRI Format
		 */
	
		int len=13;// The four bytes of the header + 1 of 
		if (localNodeDescriptors!=null){
			localNodeDescriptors.encode();
			len=len+localNodeDescriptors.getTotalTLVLength();		
		}
		
		if(OSPFRouteType!=null){
			OSPFRouteType.encode();
			len = len + OSPFRouteType.getTotalTLVLength();
		}
		
		if(ipReachability!=null){
			ipReachability.encode();
			len = len + ipReachability.getTotalTLVLength();
		}
		
		this.setTotalNLRILength(len); 
		//len = len+1; //Length (1 octet, NRLI) 
		this.setLength(len);
		this.bytes=new byte[len];
		this.encodeHeader();
	
		this.bytes[4]=(byte)protocolID;
		this.bytes[5]=(byte)(routingUniverseIdentifier>>>56 & 0xFF);
		this.bytes[6]=(byte)(routingUniverseIdentifier>>>48 & 0xFF);
		this.bytes[7]=(byte)(routingUniverseIdentifier >>> 40 & 0xFF);
		this.bytes[8]=(byte)(routingUniverseIdentifier>>>32 & 0xFF);
		this.bytes[9]=(byte)(routingUniverseIdentifier>>>24 & 0xFF);
		this.bytes[10]=(byte)(routingUniverseIdentifier >>> 16 & 0xFF);
		this.bytes[11]=(byte)(routingUniverseIdentifier >>>8 & 0xFF);
		this.bytes[12]=(byte)(routingUniverseIdentifier & 0xFF);
		
		int offset=13;
		
		if (localNodeDescriptors!=null){
			System.arraycopy(localNodeDescriptors.getTlv_bytes(), 0, this.bytes, offset,localNodeDescriptors.getTotalTLVLength());
			offset=offset+localNodeDescriptors.getTotalTLVLength();
		}
		
		if (OSPFRouteType!=null){
			System.arraycopy(OSPFRouteType.getTlv_bytes(), 0, this.bytes, offset, OSPFRouteType.getTotalTLVLength());
			offset=offset+OSPFRouteType.getTotalTLVLength();
		}
		
		if (ipReachability!=null){
			System.arraycopy(ipReachability.getTlv_bytes(), 0, this.bytes, offset, ipReachability.getTotalTLVLength());
			offset=offset+ipReachability.getTotalTLVLength();
		}
	
	}

	private void decode() { 
        int offset = 4; 
        this.protocolID = this.bytes[offset] & 0xFF;
        log.info("DECODING PREFIX: ProtocolID=" + this.protocolID + " at offset=" + offset);
        offset = offset + 1; 
        StringBuilder hexIdent = new StringBuilder();
        for(int i=0; i<8; i++) {
            hexIdent.append(String.format("%02X ", this.bytes[offset + i]));
        }
        log.info("RAW IDENTIFIER BYTES: " + hexIdent.toString());

        long identifier = 0;
        for (int i = 0; i < 8; i++) {
            identifier <<= 8;
            identifier |= (this.bytes[offset + i] & 0xFFL);
        }
        
        this.setRoutingUniverseIdentifier(identifier);
        log.info("DECODED IDENTIFIER RESULT: " + this.routingUniverseIdentifier);
        offset = offset + 8;

     
        this.localNodeDescriptors = new LocalNodeDescriptorsTLV(this.bytes, offset);
        offset = offset + localNodeDescriptors.getTotalTLVLength();
        
       
        boolean fin = false;
        if (offset >= (this.getTotalNLRILength())) {
            fin = true;
        }
        
        while (!fin) {
            int subTLVType = BGP4TLVFormat.getType(bytes, offset);
            int subTLVLength = BGP4TLVFormat.getTotalTLVLength(bytes, offset);
            
            log.info("Found Prefix SubTLV: Type=" + subTLVType + " Length=" + subTLVLength);

            switch (subTLVType) {
                case PrefixDescriptorSubTLVTypes.PREFIX_DESCRIPTOR_SUB_TLV_TYPE_IPV4_REACHABILITY_INFO:
                    this.ipReachability = new IPReachabilityInformationTLV(bytes, offset);
                    log.info("Prefix Reachability decoded: " + this.ipReachability.toString());
                    break;
                case PrefixDescriptorSubTLVTypes.PREFIX_DESCRIPTOR_SUB_TLV_TYPE_OSPF_ROUTE_TYPE:
                    this.OSPFRouteType = new OSPFRouteTypeTLV(bytes, offset);
                    break;
                default:
                    log.warn("Unknown Prefix SubTLV found: " + subTLVType);
            }
        
            offset = offset + subTLVLength;
            if (offset >= (this.getTotalNLRILength())) {
                fin = true;
            }
        }
    }

	public int getProtocolID() {
		return protocolID;
	}

	public void setProtocolID(int protocolID) {
		this.protocolID = protocolID;
	}

	public LocalNodeDescriptorsTLV getLocalNodeDescriptors() {
		return localNodeDescriptors;
	}

	public void setLocalNodeDescriptors(LocalNodeDescriptorsTLV localNodeDescriptors) {
		this.localNodeDescriptors = localNodeDescriptors;
	}
	
	public void setRoutingUniverseIdentifier(long level3identifier) {
		this.routingUniverseIdentifier = level3identifier;
		
	}
	
	public long getRoutingUniverseIdentifier() {
		return routingUniverseIdentifier;
	}



	public OSPFRouteTypeTLV getOSPFRouteType() {
		return OSPFRouteType;
	}



	public void setOSPFRouteType(OSPFRouteTypeTLV oSPFRouteType) {
		OSPFRouteType = oSPFRouteType;
	}



	public IPReachabilityInformationTLV getIpReachability() {
		return ipReachability;
	}



	public void setIpReachability(
			IPReachabilityInformationTLV ipReachability) {
		this.ipReachability = ipReachability;
	}

	@Override
    public String toString() {
        StringBuilder sb = new StringBuilder(200);
        sb.append("IPv4PrefixNLRI [Protocol-ID=").append(protocolID)
          .append(", RoutingIdentifier=").append(routingUniverseIdentifier);
        
        if (localNodeDescriptors != null) {
            sb.append(", ").append(localNodeDescriptors.toString());
        }
        
        if (ipReachability != null) {
            sb.append(", ").append(ipReachability.toString());
        }
        
        if (OSPFRouteType != null) {
            sb.append(", ").append(OSPFRouteType.toString());
        }
        
        sb.append("]");
        return sb.toString();
    }

	

}
