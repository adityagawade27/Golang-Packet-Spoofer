package main 

import (
      "fmt"
      "net"
      "os"
      "github.com/google/gopacket"
      "github.com/google/gopacket/pcap"
      "github.com/google/gopacket/layers"
      "time"
      "encoding/json"
      "io/ioutil"
)

var (
	device      string = conf.Local.Device
	snap_len    int32  = 1600
	promiscuous bool = false 
	err         error 
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
	option      gopacket.SerializeOptions 
	payload     []byte = []byte{66,33,66,99}       // Identifier
	conf        Config
	filename    string  = "pspoofer_conf.json" 
)

type Config struct {
	Local struct {
		Device string  `json:"device"`  
	}  `json:local`
	Packet struct {
		SrcIP string   `json:"srcIP"` 
		DstIP string   `json:"dstIP"`
		SrcMAC string  `json:"srcMAC"`
		DstMAC string  `json:"dstMAC"`
		TTL    int     `json:"TTL"`
		SrcPort int    `json:"srcPort"`
		DstPort int    `json:"dstPort"`
	} `json:"packet"`
}

func FatalError(err error){
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}


func getConfig(filename string) Config {
	confFile, err := ioutil.ReadFile(filename)
	FatalError(err)
	json.Unmarshal(confFile, &conf)
	return conf
}

func buildTCPPacket() (gopacket.SerializeBuffer) {
	// Fill in the alyer information 
	ethLayer := &layers.Ethernet{
		          SrcMAC: net.HardwareAddr(conf.Packet.SrcMAC), 
	              DstMAC: net.HardwareAddr(conf.Packet.DstMAC)}

	ipLayer := &layers.IPv4{
		         SrcIP: net.ParseIP(conf.Packet.SrcIP),
	             DstIP: net.ParseIP(conf.Packet.DstIP),
	             TTL: uint8(conf.Packet.TTL)}

	tcpLayer := &layers.TCP{
		          SrcPort: layers.TCPPort(conf.Packet.SrcPort),
	              DstPort: layers.TCPPort(conf.Packet.DstPort)}

	// Combine Layers to Create Packet               

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, option, 
		     ethLayer, ipLayer, tcpLayer, 
		     gopacket.Payload(payload))

	return buffer

}

func main(){
	// Open Device to Send Packet 
	handle, err = pcap.OpenLive(device, snap_len, promiscuous, timeout)
	FatalError(err)


	// Send packet over device 
	packetBuffer := buildTCPPacket()
	err = handle.WritePacketData(packetBuffer.Bytes())
	FatalError(err)
	fmt.Println("Packet Sent")

}
