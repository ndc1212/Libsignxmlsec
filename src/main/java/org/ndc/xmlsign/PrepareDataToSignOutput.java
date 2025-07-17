package org.ndc.xmlsign;

public class PrepareDataToSignOutput {
    public String key;
    public String dataToSign;

    public PrepareDataToSignOutput(String key, String dataToSign) {
        this.key = key;
        this.dataToSign = dataToSign;
    }
}
