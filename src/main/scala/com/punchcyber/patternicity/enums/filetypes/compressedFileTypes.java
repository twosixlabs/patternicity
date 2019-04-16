package com.punchcyber.patternicity.enums.filetypes;

@SuppressWarnings("unused")
public enum compressedFileTypes {
    GZIP("gz"),
    TAR("tar"),
    ZIP("zip"),
    BZIP2("bz2"),
    UNSUPPORTED();
    
    private String fileExtension;
    
    compressedFileTypes(String fileExtension) {
        this.fileExtension = fileExtension;
    }
    
    compressedFileTypes() {}
}
