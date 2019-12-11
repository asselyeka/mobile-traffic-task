package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "log"
)

var (
    pcapFile string = "capture-Bridge0-May 24 12-50-28.pcapng"
    handle   *pcap.Handle
    err      error
)

func main() {
    // Open file 
    handle, err = pcap.OpenOffline(pcapFile)
    if err != nil { log.Fatal(err) }
    defer handle.Close()

    // Total packet sum
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    packetCount := 0
    for range packetSource.Packets() {
        packetCount ++
    }
    fmt.Printf("общее число пакетов: %d\n",packetCount)

    // Open file 
    handle, err = pcap.OpenOffline(pcapFile)
    if err != nil { log.Fatal(err) }
    defer handle.Close()

    // Set filter
    var filter string = "udp"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }
    //fmt.Println("Only capturing UDP port")
    // UDP port packet sum
    udpPacketSource := gopacket.NewPacketSource(handle, handle.LinkType())
    udpPacketCount := 0
    udpPacketLen := 0
    for packet := range udpPacketSource.Packets() {
        udpPacketCount ++
        m := packet.Metadata()
        udpPacketLen += m.CaptureInfo.CaptureLength
    }
    avrLen := 0
    if udpPacketCount != 0 {
        avrLen = udpPacketLen/udpPacketCount
    }
    fmt.Printf("число пакетов протокола UDP: %d, и их средняя длина: %d\n", udpPacketCount, avrLen)
}