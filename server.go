package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device       string = "\\Device\\NPF_{300A26C2-6E66-4C2A-8BF7-8142661B27A2}"
	snapshot_len int32  = 1024
	promiscuos   bool   = false
	err          error
	timeout      time.Duration = -1
	handle       *pcap.Handle
)

func main() {
	devicess, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, devices := range devicess {
		fmt.Println(devices.Name, ":", devices.Description)
	}

	handle, err := pcap.OpenLive(device, snapshot_len, promiscuos, timeout)

	if err != nil {
		log.Fatal(err)
		defer handle.Close()
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		printPacketInfo(packet)
	}
}

func printPacketInfo(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)

	if tcpLayer != nil && ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		tcp, _ := tcpLayer.(*layers.TCP)
		if ip.SrcIP.String() == "117.62.241.165" {
			fmt.Println(tcp.Contents)
		}
	}
}

func getIpInfo(ip net.IP) string {
	resp, err := http.Get("http://ip.ws.126.net/ipquery?ip=" + ip.String())
	if err != nil {
		log.Fatal(err)
		defer resp.Body.Close()
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	return string(body)
}
