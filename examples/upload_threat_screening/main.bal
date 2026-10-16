import ballerina/io;
import ballerinax/cloudmersive.virusscan;

configurable string apiKey = ?;
configurable string filePath = ?;
configurable string websiteUrl = ?;
configurable boolean allowMacros = false;

public function main() returns error? {
    virusscan:Client scanner = check new ({apikey: apiKey});

    // Step 1: Run the basic virus scan on the uploaded file.
    byte[] content = check io:fileReadBytes(filePath);
    virusscan:VirusScanResult basic = check scanner->scanFile({inputFile: {fileContent: content, fileName: filePath}});
    boolean clean = basic.cleanResult ?: false;
    io:println("Basic scan clean: ", clean);

    // Step 2: Apply a strict advanced policy only if the basic scan passed.
    if clean {
        virusscan:VirusScanAdvancedResult advanced = check scanner->scanFileAdvanced(
            {inputFile: {fileContent: content, fileName: filePath}},
            {allowExecutables: false, allowScripts: false, allowMacros, allowHtml: false});
        io:println("Advanced scan clean: ", advanced.cleanResult ?: false);
        io:println("Verified file format: ", advanced.verifiedFileFormat ?: "unknown");
    } else {
        virusscan:VirusFound[] found = basic.foundViruses ?: [];
        foreach virusscan:VirusFound virus in found {
            io:println("Threat found: ", virus.virusName ?: "unknown");
        }
    }

    // Step 3: Check the page the file was linked from.
    virusscan:WebsiteScanResult website = check scanner->scanWebsite({url: websiteUrl});
    io:println("Website clean: ", website.cleanResult ?: false, ", threat type: ", website.websiteThreatType ?: "None");
}
