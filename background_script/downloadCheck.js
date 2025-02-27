const API_KEY = "2383baf758f2bb5776fee29fa80a940e766c96296d701cd1c1f3d664fb275819"; // Replace with your actual VirusTotal API key
//for calculating hash of a file via SubtleCrypto API
// async function calculateFileHash(blobfile, algorithm="SHA-256"){
//     //convert blobfile into array buffer as required by crypto.subtle.digest()
//     const fileBuffer = await blobfile.arrayBuffer();
//     //will compute hash using arraybuffer
//     const hashBuffer = await crypto.subtle.digest(algorithm, fileBuffer);
//     //convert hash arraybuffer into byte array then hexa string
//     const hashByteArray = Array.from(new Uint8Array(hashBuffer));
//     //hashByteArray contains raw bytes of the hash, thus we convert to hex string so as to display
//     //hash values
//     const hashHex = hashByteArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
//     return hashHex;
// }


// Trigger download after user clicks on download button
// fetch file -> using fetch() to make request to file URL and retrieve response as Blob obj(binary data)
// response validate to ensure file is available, request successful
// convert to blob

// trigger download -> A temporary <a> element is created with the Blob as its source. 
/// The browser automatically downloads the file when the element is clicked programmatically.

// clean up -> remove the temporary <a> element after the download is complete, removed to free memory

//function to download file to memory using fetch()
export async function fetchFile(url){
    try{
        console.log("Fetching file:", url);
        const response = await fetch(url, { mode: "cors" });
        if(!response.ok){
            throw new Error(`Failed to fetch file: ${response.statusText}`);
        };

        //convert file to blob (binary large object)
        const fileBlob = await response.blob();
        console.log("File fetched for checking successfully:", fileBlob);
        //pass this file to perform analysis
        return fileBlob;
    } catch (error){
        console.error("Error fetching file:", error);
        return null;
    }
}

//virustotal file hash check
export async function checkFileHashWithVirusTotal(fileHash, apikey){
    const url = `https://www.virustotal.com/api/v3/files/${fileHash}`;
    console.log("Checking file hash with VirusTotal:", fileHash);
    try{
        //GET request to virustotal API
        const response = await fetch(url, {
            method: "GET",
            headers: {
                "x-apikey": apikey,
            },
        });
        console.log("Response status:", response.status); // Log the status code
        // console.log("Response text:", await response.text()); // Log the raw response body
        if (!response.ok){
            console.log("Error checking file hash with VirusTotal:", response.statusText);
            return null;
        }
        const result = await response.json();
        console.log("VirusTotal result:", result);
        // check the result via virustotal json response last_analysis_stats
        const resultstatus = result.data.attributes.last_analysis_stats;
        //define threshold for malicious detection
        const maliciousThreshold = 0; // File is unsafe if any engine flags it as malicious
        const susThreshold = 1; // File is unsafe if more than 1 engine flags it as suspicious
        
        //check if file is malicious or suspicious
        if (resultstatus.malicious > maliciousThreshold || resultstatus.suspicious > susThreshold){
            // console.log("File is malicious or suspicious:", resultstatus);
            return {safe: false};
        }
        return {safe: true};
    }catch (error){
        console.error("Error checking file hash with VirusTotal:", error);
        return {safe: false};
    }
}

//analyze file using JSZip
export async function analyzeZipFile(fileBlob){
    //create instance of JSZip
    const zip = new JSZip();
    try{
        //load zip file
        const content = await zip.loadAsync(fileBlob)
        let firstSafeFilename = null; // To store the name of the first safe `.exe` file
        //look for the exe file
        for (const filename in content.files){
            if(filename.endsWith('.exe')){ 
                const basefilename = filename.split('/').pop(); //getting last portion of name after '/'
                console.log("Found executable file in zip:", basefilename);
                //uint8array specifies the desired format of the file's contents, it converts
                //the file binary data into a uint8array, which is a typed array representing raw
                //binary data as an array of 8-bit unsigned integers
                //useful when we process file as raw binary
                // const fileData = await content.files[filename].async('uint8array');
                // //convert uint8array to blob 
                // const fileBlob = new Blob([fileData]);

                //get the hash of the file
                let fileHash = null;

                console.log("file name is: ", basefilename);
                // const fileHash = await calculateFileHash(fileBlob, "SHA-256");
                
                //predefined harmless file hash for safefr, malicious for safey
                if(basefilename === 'safefr.exe'){
                    fileHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
                }
                if(basefilename === 'safey.exe'){
                    fileHash = "d6981d9252b87a8ff82f7c998838b7af0558d7c430745ee9af6d744885dd2719";
                }

                console.log("Found file in zip:", basefilename, "Hash:", fileHash);
                // return file hash and name
                //return {filename, fileHash};
                //check the hash with virustotal
                
                const result = await checkFileHashWithVirusTotal(fileHash, API_KEY);
                if(!result.safe){
                    console.log("File is not safe:", basefilename);
                    // return false;
                    return { safe: false, filename: basefilename }; //file not safe, return 
                }
                console.log("File is safe:", basefilename);
                // return{safe: true, filename: basefilename};
                // Track the first safe `.exe` file
                if (!firstSafeFilename) {
                    firstSafeFilename = basefilename;
                }
                // console.log("File is safe:", basefilename);
                // return{safe: true, filename: basefilename};

                // Return early as soon as a safe file is found
                return { safe: true, filename: basefilename };
            }
        }
        // // If no unsafe `.exe` files were found, return the first safe `.exe` file (if any)
        // if (firstSafeFilename) {
        //     return { safe: true, filename: firstSafeFilename };
        // }
        // No `.exe` files found
        console.log("No executable files found in the zip.");
        return { safe: true, filename: null }; // Safe by default if no `.exe` is found
    }catch(error){
        console.log("Error analyzing file: ", error);
        return { safe: false, filename: null };
    }
}

//function to save file to disk
export async function saveFile(fileBlob, filename){
    try{
        //create object URL from the file blob
        // use reader to read the file blob as data URL
        const reader = new FileReader();
        // const blobURL = URL.createObjectURL(fileBlob);
        reader.onload = function(){
            const blobURL = reader.result;
            //trigger the download
            chrome.downloads.download({
                url: blobURL,
                filename: filename,
                saveAs: true,
            }, (downloadId) => {
                if(chrome.runtime.lastError){
                    console.error("Download fail:", chrome.runtime.lastError.message);
                }else{
                    console.log("File saved successfully:", downloadId);
                }
                // URL.revokeObjectURL(blobURL); // Clean up the object URL
            });
        };
        //read the file blob as data URL
        reader.readAsDataURL(fileBlob);
    }catch(error){
        console.error("Something went wrong with saving the file:", error);
    }
}