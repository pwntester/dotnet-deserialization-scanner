package burp;

import org.apache.commons.lang3.ArrayUtils;
import java.util.Arrays;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IScannerCheck {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private PrintWriter stdout;
    private PrintWriter stderr;
    
    private static final byte[] serializeMagic = new byte[]{(byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff};
    private static final byte[] base64Magic = {(byte)0x41, (byte)0x41, (byte)0x45, (byte)0x41, (byte)0x41, (byte)0x41, (byte)0x44};
    private static final byte[] asciiHexMagic = {(byte)0x30, (byte)0x30, (byte)0x30, (byte)0x31,(byte)0x30, (byte)0x30, (byte)0x30, (byte)0x30, (byte)0x30, (byte)0x30, (byte)0x66, (byte)0x66, (byte)0x66, (byte)0x66, (byte)0x66, (byte)0x66};
    //private static final byte[] gzipMagic = {(byte)0x1f, (byte)0x8b};
    //private static final byte[] base64GzipMagic = {(byte)0x48, (byte)0x34, (byte)0x73, (byte)0x49};

    private static final String passiveScanIssueName = ".NET Unsafe Deserialization";
    private static final String passiveScanSeverity = "High";
    private static final String passiveScanConfidence = "Certain";
    private static final String passiveScanIssueDetail = "Serialized .NET objects have been detected in the body"+
        						" or in the parameters of the request. If the server application does "+
        						" not check on the type of the received objects before"+
        						" the deserialization phase, it may be vulnerable to the .NET Deserialization"+
        						" Vulnerability.";
    private static final String passiveScanRemediationDetail = "Do not deserialize untrusted data.";
       
    
    // implement IBurpExtender
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName(".NET Deserialization Scanner");
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.registerScannerCheck(this);
        stdout.println(".NET Deserialization Scanner v0.1");
    }
    
    // implement IScannerCheck
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        List<IScanIssue> issues = new ArrayList<IScanIssue>();

        // FIRST CHECK IN REQUEST

        byte[] request = baseRequestResponse.getRequest();
        int magicPos = helpers.indexOf(request, serializeMagic, false, 0, request.length);
    	int magicPosBase64 = helpers.indexOf(request, base64Magic, false, 0, request.length);
    	int magicPosAsciiHex = helpers.indexOf(request, asciiHexMagic, false, 0, request.length);
        //int magicPosBase64Gzip = helpers.indexOf(request, base64GzipMagic, false, 0, request.length);
        //int magicPosGzip = helpers.indexOf(request, gzipMagic, false, 0, request.length);

        if(magicPos > -1 || magicPosBase64 > -1 || magicPosAsciiHex > -1) { /* || magicPosBase64Gzip > -1 || magicPosGzip > -1 */
            //Add standard issues
            List<int[]> responseMarkers = new ArrayList<int[]>();

            int startPos = 1;
            int endPos = -1;

            byte[] expectedStartChars = new byte[]{'"', '\'', '\n', '{', '(', '[', '<', '>', '='};

            if (magicPos > -1) startPos = magicPos;
            else if (magicPosBase64 > -1) startPos = magicPosBase64;
            else if (magicPosAsciiHex > -1) startPos = magicPosAsciiHex;
            /*
            else if (magicPosBase64Gzip > -1) startPos = magicPosBase64Gzip;
            else if (magicPosGzip > -1) startPos = magicPosGzip;
            */

            //Extract out full object by first checking what the character before it is, e.g. " ' {
            byte[] startChar = Arrays.copyOfRange(request, startPos-1, startPos);
            byte[] endChar = new byte[1];

            String issueConfidence = passiveScanConfidence;

            //Sanity check the char to see if its a reasonable and expected value
            if (ArrayUtils.contains(expectedStartChars, startChar[0])) {
                //Run a follow up check to see if it is an open bracket in which case check for the equivalent close bracket
                if (startChar[0] == '(') endChar[0] = ')';
                else if (startChar[0] == '{') endChar[0] = '}';
                else if (startChar[0] == '[') endChar[0] = ']';
                else if (startChar[0] == '<') endChar[0] = '>';
                else if (startChar[0] == '>') endChar[0] = '<';
                else if (startChar[0] == '=') endChar[0] = ';';
                else if (startChar[0] == '"') endChar[0] = '"';
                else if (startChar[0] == '\'') endChar[0] = '\'';

                if (endChar != null) endPos = helpers.indexOf(request, endChar, false, startPos, request.length);

                // One more chance for last cookies
                if (endPos == -1 && startChar[0] == '=') {
                    endChar[0] = '\n';
                    endPos = helpers.indexOf(request, endChar, false, startPos, request.length);
                }
            } else {
                issueConfidence = "Firm";
            }

            //Check if endPos was found, otherwise set to response.length
            if (endPos == -1) endPos = startPos + 7;

            //Extract out potential object
            byte[] potentialObject = Arrays.copyOfRange(request, startPos, endPos);

            responseMarkers.add(new int[]{startPos,endPos});

            String issueName = passiveScanIssueName;
            if (magicPos > -1) issueName = passiveScanIssueName;
            else if (magicPosBase64 > -1) issueName = passiveScanIssueName + " (encoded in Base64)";
            else issueName = passiveScanIssueName + " (encoded in Ascii HEX)";

            issues.add(
                new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, responseMarkers, null) },
                    issueName,
                    passiveScanSeverity,
                    issueConfidence,
                    passiveScanIssueDetail,
                    passiveScanRemediationDetail
                )
            );
        }

        // THEN CHECK IN RESPONSE
        byte[] response = baseRequestResponse.getResponse();

        magicPos = helpers.indexOf(response, serializeMagic, false, 0, response.length);
        magicPosBase64 = helpers.indexOf(response, base64Magic, false, 0, response.length);
        magicPosAsciiHex = helpers.indexOf(response, asciiHexMagic, false, 0, response.length);
        //magicPosBase64Gzip = helpers.indexOf(response, base64GzipMagic, false, 0, response.length);
        //magicPosGzip = helpers.indexOf(response, gzipMagic, false, 0, response.length);
        
        if(magicPos > -1 || magicPosBase64 > -1 || magicPosAsciiHex > -1 /*|| magicPosBase64Gzip > -1 || magicPosGzip > -1 */) {
            //Add standard issues
            List<int[]> responseMarkers = new ArrayList<int[]>();

            int startPos = 1;
            int endPos = -1;

            byte[] expectedStartChars = new byte[]{'"', '\'', '\n', '{', '(', '[', '<', '>', '=', ' '};

            if (magicPos > -1) startPos = magicPos;
            else if (magicPosBase64 > -1) startPos = magicPosBase64;
            else if (magicPosAsciiHex > -1) startPos = magicPosAsciiHex;
            /*
            else if (magicPosBase64Gzip > -1) startPos = magicPosBase64Gzip;
            else if (magicPosGzip > -1) startPos = magicPosGzip;
            */

            //Extract out full object by first checking what the character before it is, e.g. " ' {
            byte[] startChar = Arrays.copyOfRange(response, startPos-1, startPos);
            byte[] endChar = new byte[1];

            String issueConfidence = passiveScanConfidence;

            //Sanity check the char to see if its a reasonable and expected value
            if (ArrayUtils.contains(expectedStartChars, startChar[0])) {
                //Run a follow up check to see if it is an open bracket in which case check for the equivalent close bracket
                if (startChar[0] == '(') endChar[0] = ')';
                else if (startChar[0] == '{') endChar[0] = '}';
                else if (startChar[0] == '[') endChar[0] = ']';
                else if (startChar[0] == '<') endChar[0] = '>';
                else if (startChar[0] == '>') endChar[0] = '<';
                else if (startChar[0] == '=') endChar[0] = ';';
                else if (startChar[0] == '"') endChar[0] = '"';
                else if (startChar[0] == '\'') endChar[0] = '\'';

                if (endChar != null) endPos = helpers.indexOf(response, endChar, false, startPos, response.length);

                // One more chance for last cookies
                if (endPos == -1 && startChar[0] == '=') {
                    endChar[0] = '\n';
                    endPos = helpers.indexOf(response, endChar, false, startPos, response.length);
                }
            } else {
                issueConfidence = "Firm";
            }


            //Check if endPos was found, otherwise set to response.length
            if (endPos == -1) endPos = startPos + 7;

            //Extract out potential object
            byte[] potentialObject = Arrays.copyOfRange(response, startPos, endPos);

            //Add standard issues
            responseMarkers.add(new int[]{startPos,endPos});

            String issueName = passiveScanIssueName;
            if(magicPos > -1) issueName = passiveScanIssueName + " in response";
            else if(magicPosBase64 > -1) issueName = passiveScanIssueName + " in response (encoded in Base64)";
            else issueName = passiveScanIssueName + " in response (encoded in Ascii HEX)";

            issues.add(
                new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, responseMarkers ) },
                    issueName,
                    passiveScanSeverity,
                    issueConfidence,
                    passiveScanIssueDetail,
                    passiveScanRemediationDetail
                )
            );
        }

        if(issues.size() > 0) {
        	stdout.println("Reporting " + issues.size() + " passive results");
        	return issues;
        } else {
        	return null;
        } 
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) return -1;
        else return 0;
    }
}

