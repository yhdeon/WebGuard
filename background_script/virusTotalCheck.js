const API_KEY = "2383baf758f2bb5776fee29fa80a940e766c96296d701cd1c1f3d664fb275819"; // Replace with your actual VirusTotal API key

export async function checkUrlWithVirusTotal(url) {
    console.log("🔍 Checking URL with VirusTotal:", url);
    try {
      const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: "POST",
        headers: {
          accept: 'application/json',
          'content-type': 'application/x-www-form-urlencoded',
          'x-apikey': API_KEY
        },
        body: new URLSearchParams({ url: url })
      });
      if (!submitResponse.ok) {
        console.error(`Failed to submit URL: ${submitResponse.statusText}`);
        return false;
      }
      const submitData = await submitResponse.json();
      const reportId = submitData.data.id;
      await new Promise(resolve => setTimeout(resolve, 5000)); // Wait for processing
      const reportResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${reportId}`, {
        method: 'GET',
        headers: {
          accept: 'application/json',
          'x-apikey': API_KEY
        }
      });
      if (!submitResponse.ok) {
        const errorText = await submitResponse.text();
        console.error(`Failed to submit URL: ${submitResponse.status} - ${submitResponse.statusText}. Response: ${errorText}`);
        return false;
      }
      const reportData = await reportResponse.json();
      const stats = reportData.data.attributes.stats;
      return stats.malicious > 0;
    } catch (err) {
      console.error("Error in VirusTotal check:", err);
      return false;
    }
  }