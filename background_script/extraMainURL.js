export function extractMainDomain(url) {
    try {
      return new URL(url).hostname;
    } catch (err) {
      console.error("Error parsing URL:", err);
      return null;
    }
  }