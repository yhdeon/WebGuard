document.addEventListener('DOMContentLoaded', function () {
    const htmlOutput = document.getElementById('htmlOutput');
  
    // Retrieve the VirusTotal result from storage
    chrome.storage.local.get('virusTotalResult', (data) => {
      if (data.virusTotalResult) {
        const { url, isMalicious, stats } = data.virusTotalResult;
        console.log(url);
  
        if (isMalicious) {
          htmlOutput.textContent = `Warning: The URL "${url}" is malicious!\n\n${JSON.stringify(stats, null, 2)}`;
        } else {
          htmlOutput.textContent = `The URL "${url}" is safe.\n\n${JSON.stringify(stats, null, 2)}`;
        }
      } else {
        htmlOutput.textContent = "No URL has been checked yet.";
      }
    });
  });