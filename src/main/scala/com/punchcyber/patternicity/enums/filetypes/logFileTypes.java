package com.punchcyber.patternicity.enums.filetypes;

public enum logFileTypes {
    BRO("log"),
    EVTX("evtx"),
    PCAP("pcap"),
    UNSUPPORTED();
    
    private String fileExtension;
    
    logFileTypes(String fileExtension) {
        this.fileExtension = fileExtension;
    }
    
    logFileTypes() {}
}
